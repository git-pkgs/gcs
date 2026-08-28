# gcs

`gcs` implements Google Cloud Storage object operations through the JSON API. Its direct runtime dependencies are `cloud.google.com/go/compute/metadata` and `golang.org/x/oauth2`.

## Install

```bash
go get github.com/git-pkgs/gcs
```

## Write and read objects

```go
ctx := context.Background()
bucket, err := gcs.OpenBucket(ctx, "gs://my-bucket")
if err != nil {
	return err
}

_, err = bucket.Write(ctx, "packages/example.txt", strings.NewReader("content"))
if err != nil {
	return err
}

reader, err := bucket.Open(ctx, "packages/example.txt")
if err != nil {
	return err
}
defer reader.Close()
```

`Write` returns the number of bytes uploaded and sends each object as one non-resumable media upload. Retrying after a failed request starts the upload again.

`Open`, `Exists`, `Delete`, and `Size` operate on individual object names. `Open` and `Size` return `ErrNotFound` for a missing object; `Delete` accepts one. `ListPrefix` reads object metadata by prefix, while `UsedSpace` reads every object page with only the `size` field and takes time proportional to the object count.

## Authentication

`OpenBucket` reads Application Default Credentials from attached service accounts on GKE, GCE, and Cloud Run. It also reads a file selected by `GOOGLE_APPLICATION_CREDENTIALS` or local credentials created by `gcloud auth application-default login`.

## Signed URLs

`SignedURL` generates a V2 signed URL with a service-account private key when the credential file contains one. For Workload Identity and impersonated credentials, signing calls the IAM Credentials `signBlob` API and requires permission to sign blobs. The method returns `ErrSignedURLUnsupported` for the emulator and plain user credentials that do not impersonate a service account.

## Emulator

Set `STORAGE_EMULATOR_HOST` to the address of a Cloud Storage emulator. The value may include an `http://` or `https://` scheme.

## License

MIT
