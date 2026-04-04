vcl 4.1;

backend default {
    .host = "nginx";
    .port = "80";
}

sub vcl_recv {
    if (req.method == "PURGE") {
        return (purge);
    }
}

sub vcl_deliver {
    set resp.http.X-Cache = "HIT";
    set resp.http.X-Cache-Hits = obj.hits;
    set resp.http.X-Served-By = "varnish-edge";
}
