# Filer

Filer is a lightweight tool that enables file downloads and uploads over a network.

## Usage

```sh
cd path/to/a/directory
go run github.com/k11v/filer
```

These commands start the Filer server, allowing for file downloads and uploads to the server's working directory.
Note that file uploads can overwrite existing files in this directory.

## Security

The connection is secured using a self-signed TLS certificate,
which is generated each time the server starts.
When generated, the certificate's SHA256 fingerprint is displayed in the standard output.
Users should verify that the fingerprint on the client (such as a web browser)
matches the one on the server to guard against man-in-the-middle attacks.

Additionally, since anyone on the network can view and overwrite the contents of
the shared directory without the need for authentication, be mindful of who has
access to the server and whether the server is exposed to the Internet or not.
