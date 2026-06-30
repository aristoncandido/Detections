#event.dataset="adc.waf"
| event.action = /not blocked/
| join(
query={ #event.dataset="fortigate.traffic" | event.action = /deny|close|block/ },
field=source.ip,
include=[destination.ip, destination.port],
mode="inner"
)
| groupBy([source.ip, Vendor.name],
function=[count(as=hits), collect([url.original, destination.ip, destination.port])])
| sort(hits, order=desc)