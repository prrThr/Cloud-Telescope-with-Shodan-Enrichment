import os
import sys
import re
import argparse
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

import geoip2.database
#solver = geoip2.database.Reader('GeoLite2-City.mmdb') #FREE
solver = geoip2.database.Reader(os.path.join(PROJECT_ROOT, 'GeoIP2-City.mmdb')) #LICENSED

import awsipranges
aws_ip_ranges = awsipranges.get_ranges()

#print("timestamp,ip.src,ip.dst,tcp.dstport,udp.dstport,icmp.type,source_country_iso_code,source_country_name,source_city_name,source_latitude,source_longitude,
#aws_country_code,aws_country_name,aws_city_name,aws_latitude,aws_longitude,aws_region")

#ipsrcfile=open("enriched_unique_source_IPs.csv","w")
#ipdstfile=open("enriched_unique_destination_IPs.csv","w")
unique_ipsrc = []
unique_ipsrc_enriched_output = []
unique_ipdst = []
unique_ipdst_enriched_output = []
cachesrc = {}
cachedst = {}
cachesrchit = 0
cachesrcmiss = 0
cachedsthit = 0
cachedstmiss = 0
#cacheglobalcounter = 0
cacheinfo = open(os.path.join(PROJECT_ROOT, 'logs', 'cacheinfo.txt'), "w")
anomalous_entries = open(os.path.join(PROJECT_ROOT, 'logs', 'anomalous_entries.csv'), "w")

FILENAME_RE = re.compile(
    r"^(?P<region>.+?)[-_](?P<ip>(?:\d{1,3}\.){3}\d{1,3})[-_](?P<date>\d{4}[-−]?\d{2}[-−]?\d{2}|\d{8})[-_](?P<time>\d{2}[-:]?\d{2}(?:[-:]?\d{2})?)$"
)
REGION_AZ_RE = re.compile(r"^(?P<base_region>.+-\d+)(?P<az>[a-z])$")

parser = argparse.ArgumentParser(description="Enriquecimento GeoIP + AWS de CSV de captura")
parser.add_argument("--region", default=None,
                    help="Região AWS de destino (ex: af-south-1). Usada como fallback quando 100% "
                         "dos IPs de destino são privados e não resolvem via GeoIP/awsipranges "
                         "( esperado em datasets com NAT transparente como e3).")
args = parser.parse_args()

_region_override = args.region
_region_from_filename = None
_detected_fallback = False


def _extract_region_from_filename(fname):
    """Extrai a região AWS a partir do nome do arquivo de captura (ex: af-south-1a-13.244.104.42-20231219-2011)."""
    stem = fname
    for ext in ('.pcap.gz', '.pcap.txt', '.pcap'):
        if stem.endswith(ext):
            stem = stem[:-len(ext)]
            break
    m = FILENAME_RE.match(stem)
    if m:
        region_raw = m.group("region")
        az_m = REGION_AZ_RE.match(region_raw)
        if az_m:
            return az_m.group("base_region")
        return region_raw
    return None


lines_buf = []
for rawline in sys.stdin:
    line = rawline.rstrip()
    parts = line.split(',')
    if len(parts) == 7 and len(parts[1].split('.')) == 4 and len(parts[2].split('.')) == 4:
        fname = parts[0]
        r = _extract_region_from_filename(fname)
        if r:
            _region_from_filename = r
        lines_buf.append(rawline)
    else:
        lines_buf.append(rawline)

total_dst = 0
unknown_dst = 0
region_override_source = None

for rawline in lines_buf:
    line = rawline.rstrip()
    parts = line.split(',')
    if len(parts) == 7 and len(parts[1].split('.')) == 4 and len(parts[2].split('.')) == 4:
        total_dst += 1
        ipdst = parts[2]
        try:
            geoip_destination = solver.city(ipdst)
            aws_response = aws_ip_ranges.get(ipdst)
            reg = str(aws_response.region) if aws_response and aws_response.region else None
        except Exception:
            reg = None
        if not reg:
            unknown_dst += 1

if total_dst > 0 and unknown_dst == total_dst:
    _detected_fallback = True
    if _region_from_filename:
        _region_override = _region_from_filename
        region_override_source = "filename"
    elif _region_override:
        region_override_source = "cli"
    else:
        region_override_source = None
    if _region_override:
        print(f"[2_enrich_csv] FALLBACK ATIVADO: 100% das linhas com região de destino desconhecida "
              f"(total={total_dst}, unknown={unknown_dst}). Usando região '{_region_override}' "
              f"(fonte: {region_override_source}).", file=sys.stderr)
    else:
        print(f"[2_enrich_csv] AVISO: 100% das linhas com região de destino desconhecida "
              f"(total={total_dst}, unknown={unknown_dst}). Nenhuma --region fornecida; "
              f"mantendo 'Unknown'.", file=sys.stderr)
else:
    if _region_override:
        _detected_fallback = False
        _region_override = None

for rawline in lines_buf:
    # cacheglobalcounter+=1
    # if cacheglobalcounter > 250000:
    #     cachesrc.clear()
    #     cachedst.clear()
    #     cacheglobalcounter=0

    line=rawline.rstrip()
    line=line.split(',')
    if len(line) == 7 and len(line[1].split('.')) == 4 and len(line[2].split('.')) == 4: #DIRTY IP CHECK
        timestamp=str(line[0])
        ipsrc=str(line[1])
        ipdst=str(line[2])
        tcpdstport=str(line[3])
        tcpdstflags=str(line[4])
        udpdstport=str(line[5])
        icmptype=str(line[6])

        if not ipsrc in cachesrc.keys():
            cachesrcmiss+=1
            try:
                geoip_source = solver.city(ipsrc)
            except:
                cachesrc[ipsrc] = {}
                cachesrc[ipsrc]['iso_code'] = "ZZ" #6
                cachesrc[ipsrc]['country_name'] = "ZZ Country" #7
                cachesrc[ipsrc]['city_name'] = "Unknown" #8
                cachesrc[ipsrc]['latitude'] = "-99" #9 
                cachesrc[ipsrc]['longitude'] = "-99" #10
            else:
                cachesrc[ipsrc] = {}
                cachesrc[ipsrc]['iso_code'] = str(geoip_source.country.iso_code)#6
                cachesrc[ipsrc]['country_name'] = str(geoip_source.country.name)#7
                if geoip_source.city.name:
                    cachesrc[ipsrc]['city_name'] = str(geoip_source.city.name)
                    cachesrc[ipsrc]['city_name'] = cachesrc[ipsrc]['city_name'].replace("'"," ")#8
                else:
                    cachesrc[ipsrc]['city_name'] = 'Unknown'#8
                cachesrc[ipsrc]['latitude'] = str(geoip_source.location.latitude)#9
                cachesrc[ipsrc]['longitude'] = str(geoip_source.location.longitude)#10
        else:
            cachesrchit+=1

        line.append(cachesrc[ipsrc]['iso_code']) #7
        source_country_iso_code=cachesrc[ipsrc]['iso_code']#7
        line.append(cachesrc[ipsrc]['country_name'])#8
        source_country_name=cachesrc[ipsrc]['country_name']#8
        line.append(cachesrc[ipsrc]['city_name'])#9
        source_city_name=str(cachesrc[ipsrc]['city_name'])#9
        line.append(cachesrc[ipsrc]['latitude'])#10
        source_latitude=cachesrc[ipsrc]['latitude']#10
        line.append(cachesrc[ipsrc]['longitude'])#11
        source_longitude=cachesrc[ipsrc]['longitude']#11

        if not ipdst in cachedst.keys():
            cachedstmiss+=1
            try:
                geoip_destination = solver.city(ipdst)
            except:
                cachedst[ipdst] = {}
                cachedst[ipdst]['iso_code'] = "ZZ" #12
                cachedst[ipdst]['country_name'] = "ZZ Country" #13
                cachedst[ipdst]['city_name'] = "Unknown" #14
                cachedst[ipdst]['latitude'] = "-9999" #15
                cachedst[ipdst]['longitude'] = "-9999" #16
            else:
                cachedst[ipdst] = {}
                cachedst[ipdst]['iso_code'] = str(geoip_destination.country.iso_code)#12
                cachedst[ipdst]['country_name'] = str(geoip_destination.country.name)#13
                if geoip_destination.city.name:
                    cachedst[ipdst]['city_name'] = str(geoip_destination.city.name)
                    cachedst[ipdst]['city_name'] = cachedst[ipdst]['city_name'].replace("'"," ")#14
                else:
                    cachedst[ipdst]['city_name'] = 'Unknown'#14
                cachedst[ipdst]['latitude'] = str(geoip_destination.location.latitude)#15
                cachedst[ipdst]['longitude'] = str(geoip_destination.location.longitude)#16

            if _detected_fallback and _region_override:
                cachedst[ipdst]['region'] = _region_override
            else:
                try:
                    aws_response = aws_ip_ranges.get(ipdst)
                    cachedst[ipdst]['region'] = str(aws_response.region)
                except:
                    cachedst[ipdst]['region'] = "Unknown" #17

        else:
            cachedsthit+=1
                
        line.append(cachedst[ipdst]['iso_code']) #12
        aws_country_code=cachedst[ipdst]['iso_code'] #12
        line.append(cachedst[ipdst]['country_name']) #13
        aws_country_name=cachedst[ipdst]['country_name'] #13
        line.append(cachedst[ipdst]['city_name']) #14
        aws_city_name=cachedst[ipdst]['city_name']#14
        line.append(cachedst[ipdst]['latitude']) #15
        aws_latitude=cachedst[ipdst]['latitude'] #15
        line.append(cachedst[ipdst]['longitude']) #16
        aws_longitude=cachedst[ipdst]['longitude'] #16
        line.append(cachedst[ipdst]['region']) #17
        aws_region=cachedst[ipdst]['region'] #17


        #generate list of unique source and destination IPs
        # You can comment if not using Neo4j for graph-based analysis
        # if not ipsrc in unique_ipsrc:
        #     unique_ipsrc.append(ipsrc)
        #     enriched_source=ipsrc + "," + source_country_iso_code + "," + source_country_name + "," + source_city_name + "," + source_latitude + "," + source_longitude
        #     unique_ipsrc_enriched_output.append(enriched_source)
        # if not ipdst in unique_ipdst:
        #     unique_ipdst.append(ipdst)
        #     enriched_destination=ipdst + "," + aws_country_code + "," + aws_country_name + "," + aws_city_name + "," + aws_latitude + "," + aws_longitude + "," + aws_region
        #     unique_ipdst_enriched_output.append(enriched_destination)

        output=timestamp + "," + ipsrc + "," + ipdst + "," + tcpdstport + "," + tcpdstflags + "," + udpdstport + "," + icmptype + "," + source_country_iso_code + "," + source_country_name + "," + source_city_name + "," + source_latitude + "," + source_longitude + "," + aws_country_code + "," + aws_country_name + "," + aws_city_name + "," + aws_latitude + "," + aws_longitude + "," + aws_region
        print(output)
    else:
        anomalous_entries.write(rawline)

solver.close()
anomalous_entries.close()

# for ip in unique_ipsrc_enriched_output:
#     ipsrcfile.write(ip)
#     ipsrcfile.write("\n")

# for ip in unique_ipdst_enriched_output:
#     ipdstfile.write(ip)
#     ipdstfile.write("\n")

# ipsrcfile.close()
# ipdstfile.close()

cacheinfo.write("Source IP stats" + "" + "\n")
cacheinfo.write("Source IP addresses cached: " + str(len(cachesrc)) + "\n")
cacheinfo.write("Source IP cache hit: " + str(cachesrchit) + "\n")
cacheinfo.write("Source IP cache miss: " + str(cachesrcmiss) + "\n")
cacheinfo.write("\n")
cacheinfo.write("AWS IP stats" + "" + "\n")
cacheinfo.write("AWS IP addresses cached: " + str(len(cachedst)) + "\n")
cacheinfo.write("AWS IP cache hit: " + str(cachedsthit) + "\n")
cacheinfo.write("AWS IP cache miss: " + str(cachedstmiss) + "\n")
cacheinfo.write("\n")
cacheinfo.close()
