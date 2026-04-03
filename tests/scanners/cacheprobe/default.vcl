vcl 4.1;

backend default {
    .host = "app";
    .port = "8080";
}

sub vcl_recv {
    # Accept PURGE requests without authentication (vulnerability)
    if (req.method == "PURGE") {
        return (purge);
    }
}

sub vcl_deliver {
    # Expose cache status headers
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }
    set resp.http.X-Cache-Hits = obj.hits;
}
