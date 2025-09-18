// Package filebin provides an interface to filebin.net
package filebin

import (
    "context"
    "fmt"
    "io"
    "net/http"
    "strings"
    "time"

    "github.com/rclone/rclone/fs"
    "github.com/rclone/rclone/fs/config/configmap"
    "github.com/rclone/rclone/fs/config/configstruct"
    "github.com/rclone/rclone/fs/fshttp"
    "github.com/rclone/rclone/fs/hash"
    "github.com/rclone/rclone/lib/rest"
)

func init() {
    fs.Register(&fs.RegInfo{
        Name:        "filebin",
        Description: "Filebin.net",
        NewFs:       NewFs,
        Options: []fs.Option{{
            Name:     "endpoint",
            Help:     "Filebin endpoint URL.",
            Default:  "https://filebin.net",
            Advanced: true,
        }},
    })
}

type Options struct {
    Endpoint string `config:"endpoint"`
}

type Fs struct {
    name string
    root string
    bin  string
    opt  *Options
    srv  *rest.Client
}

type Object struct {
    fs     *Fs
    remote string
    size   int64
    sha256 string
}

type BinResponse struct {
    Files []File `json:"files"`
}

type UploadResponse struct {
    UploadedFile File `json:"file"`
}

type File struct {
    Filename string `json:"filename"`
    Bytes    int64  `json:"bytes"`
    SHA256   string `json:"sha256"`
}

func (f *Fs) Name() string                { return f.name }
func (f *Fs) Root() string                { return f.root }
func (f *Fs) String() string              { return fmt.Sprintf("filebin bin %q", f.bin) }
func (f *Fs) Precision() time.Duration    { return fs.ModTimeNotSupported }
func (f *Fs) Hashes() hash.Set            { return hash.Set(hash.SHA256) }
func (f *Fs) Features() *fs.Features {
    return &fs.Features{
        CanHaveEmptyDirectories: false,
        BucketBased:             true,
        BucketBasedRootOK:       true,
    }
}

func NewFs(ctx context.Context, name, rcloneRemotePath string, m configmap.Mapper) (fs.Fs, error) {
    opt := new(Options)
    if err := configstruct.Set(m, opt); err != nil {
        return nil, err
    }

    // Extract bin name from the path
    // Path format: {bin} only - filebin doesn't support file hierarchy
    bin := strings.Trim(rcloneRemotePath, "/")
    
    if bin == "" {
        return nil, fmt.Errorf("filebin bin name must be specified in the path, e.g., remoteName:{bin}")
    }

    if strings.Contains(bin, "/") {
        return nil, fmt.Errorf("filebin does not support file hierarchy - path should only contain the bin name")
    }

    client := fshttp.NewClient(ctx)
    srv := rest.NewClient(client).SetRoot(opt.Endpoint)
    srv.SetErrorHandler(func(resp *http.Response) error {
        if resp.StatusCode == 404 {
            return fs.ErrorObjectNotFound
        }
        return nil
    })
    srv.SetHeader("Accept", "application/json")

    return &Fs{
        name: name,
        root: "", // Always empty for bucket-based storage
        bin:  bin,
        opt:  opt,
        srv:  srv,
    }, nil
}

func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
    if f.root != "" {
        // This Fs is rooted at f.root (e.g., "somefile.txt").
        if dir != "" {
            // Trying to list a subdirectory of f.root (e.g., "f.root/dir"). Not possible for filebin.
            return nil, fs.ErrorDirNotFound
        }
        // dir == "". We are asked to list f.root itself.
        // Fetch the entire bin listing to find the f.root file.
        var binInfo BinResponse
        opts := rest.Opts{Method: "GET", Path: "/" + f.bin}
        if _, err := f.srv.CallJSON(ctx, &opts, nil, &binInfo); err != nil {
            return nil, fmt.Errorf("failed to list underlying bin %s to check for %s: %w", f.bin, f.root, err)
        }

        for _, file := range binInfo.Files {
            if file.Filename == f.root {
                // f.root exists. Return it as a single entry.
                entry := &Object{
                    fs:     f,
                    remote: file.Filename,
                    size:   file.Bytes,
                    sha256: file.SHA256,
                }
                return fs.DirEntries{entry}, nil
            }
        }
        // f.root was not found in the bin.
        return nil, fs.ErrorObjectNotFound
    }

    // f.root == "". This Fs represents the bin itself.
    if dir != "" {
        // Trying to list a subdirectory of the bin. Not supported.
        return nil, fs.ErrorDirNotFound
    }

    var binInfo BinResponse
    opts := rest.Opts{Method: "GET", Path: "/" + f.bin}
    if _, err := f.srv.CallJSON(ctx, &opts, nil, &binInfo); err != nil {
        return nil, err
    }

    var entries fs.DirEntries
    for _, file := range binInfo.Files {
        entries = append(entries, &Object{
            fs:     f,
            remote: file.Filename,
            size:   file.Bytes,
            sha256: file.SHA256,
        })
    }
    return entries, nil
}

func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
    entries, err := f.List(ctx, "")
    if err != nil {
        return nil, err
    }
    
    for _, entry := range entries {
        if entry.Remote() == remote {
            return entry.(fs.Object), nil
        }
    }
    return nil, fs.ErrorObjectNotFound
}

func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
    o := &Object{fs: f, remote: src.Remote()}
    return o, o.Update(ctx, in, src, options...)
}

func (f *Fs) Mkdir(ctx context.Context, dir string) error {
    if dir == "" {
        return nil // Root directory always exists
    }
    return fs.ErrorDirNotFound // Cannot create subdirectories
}

func (f *Fs) Rmdir(ctx context.Context, dir string) error {
    if dir != "" {
        // Cannot Rmdir a subdirectory relative to f.root or bin root, as filebin has no subdirectories.
        return fs.ErrorDirNotFound
    }

    // dir == "", so we are asked to remove the root of this Fs instance.
    if f.root != "" {
        // This Fs instance is rooted at f.root (e.g., "somefile.txt").
        // Rmdir-ing the root of such an Fs implies that f.root itself is a directory to be removed.
        // Since f.root represents a file path for filebin, this operation is invalid.
        // The file f.root should have been deleted by an Object.Remove call during the Purge phase
        // if the List method (above) correctly identified it.
        return fs.ErrorIsFile // f.root is a file, not a directory that can be Rmdir'd.
    }

    // f.root == "", so this Fs represents the bin itself. Delete the bin.
    opts := rest.Opts{Method: "DELETE", Path: "/" + f.bin}
    _, err := f.srv.Call(ctx, &opts)
    return err
}

func (o *Object) Fs() fs.Info                         { return o.fs }
func (o *Object) String() string                      { return o.remote }
func (o *Object) Remote() string                      { return o.remote }
func (o *Object) Size() int64                         { return o.size }
func (o *Object) ModTime(ctx context.Context) time.Time { return time.Time{} }
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error { return fs.ErrorCantSetModTime }
func (o *Object) Storable() bool                      { return true }

func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
    if t == hash.SHA256 {
        return strings.ToLower(o.sha256), nil
    }
    return "", hash.ErrUnsupported
}

func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
    fs.FixRangeOption(options, o.size)
    opts := rest.Opts{
        Method:  "GET",
        Path:    "/" + o.fs.bin + "/" + o.remote,
        Options: options,
    }
    
    resp, err := o.fs.srv.Call(ctx, &opts)
    if err != nil {
        return nil, err
    }
    return resp.Body, nil
}

func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error { // MODIFIED
    opts := rest.Opts{
        Method: "POST",
        Path:   "/" + o.fs.bin + "/" + o.remote,
        Body:   in,
    }

    if size := src.Size(); size >= 0 {
        opts.ContentLength = &size
    }

    var uploadResp UploadResponse
    // The Filebin API returns metadata of the uploaded file as JSON in the POST response body.
    _, err := o.fs.srv.CallJSON(ctx, &opts, nil, &uploadResp)
    if err != nil {
        return fmt.Errorf("failed to upload %s: %w", o.remote, err)
    }

    uploadedFile := uploadResp.UploadedFile

    // Update object metadata from the response
    o.size = uploadedFile.Bytes
    o.sha256 = uploadedFile.SHA256

    return nil
}

func (o *Object) Remove(ctx context.Context) error {
    opts := rest.Opts{
        Method: "DELETE",
        Path:   "/" + o.fs.bin + "/" + o.remote,
    }
    _, err := o.fs.srv.Call(ctx, &opts)
    return err
}

var (
    _ fs.Fs     = (*Fs)(nil)
    _ fs.Object = (*Object)(nil)
)