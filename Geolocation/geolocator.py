import sys
import geoip2.database
import dpkt
import socket
import simplekml
import os


def locator(pcap_obj,kml_file):
    """function to display all unique IPs and the packet count in the PCAP file and save it to JSON"""
    ip_list = []
    for ts, buf in pcap_obj:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        try:  # extract all unique IPs
            src_ip = str(socket.inet_ntoa(ip.src))
            dst_ip = str(socket.inet_ntoa(ip.dst))
            if src_ip in ip_list:
                pass
            else:
                ip_list.append(src_ip)
            if dst_ip in ip_list:
                pass
            else:
                ip_list.append(dst_ip)
        except AttributeError:
            pass

    try:
        reader = geoip2.database.Reader('GeoLite2-City_20190129.mmdb')                  # reading from db(can be redacted)
    except FileNotFoundError:
        print(f'[!]DB file not in current directory or with a different file name')
        sys.exit(1)
    area = []
    longitude = []
    latitude = []
    ips = []
    for ip_addr in ip_list:
        try:
            rec = reader.city(ip_addr)                                              # reading IP
            country = rec.country.iso_code                                          # assigning country and city
            city = rec.city.name
            if city is None and country is None:
                area.append('Unknown')
            elif city is None:
                area.append(f'Unknown city:{country}')                              # looking for unknown country
            elif country is None:
                area.append(f'Unknown country:{city}')                              # looking for unknown city
            else:
                area.append(f'{city} {country}')

            longitude.append(rec.location.longitude)
            latitude.append(rec.location.latitude)
            ips.append(ip_addr)
        except geoip2.errors.AddressNotFoundError:
            pass

    try:
        kml = simplekml.Kml()
        final_path = str(os.getcwd() + os.sep + kml_file)           # defining full canonical path
        for i in range(0, len(ips)):
            kml.newpoint(name=(area[i]),
                         coords=[(longitude[i], latitude[i])],
                         description=f'[+] Location = {area[i]}\n IP: {ips[i]}')
        kml.save(final_path)
        print(f"[+] Writing IP locations to {kml_file}")                            # writing data to a KML file
        print(f"[+] Opening Google Earth with:{kml_file}\n")                        # reading file with google earth
        try:
            os.startfile(final_path)
        except OSError:
            print(f'[!] Warning: Google Earth must be installed to open the kml')
    except FileNotFoundError:
        pass


def main():
    print("="*60)
    print(f'\n---------------------Simple Geolocator---------------------\n')
    print("="*60)
    print(f'[!]Usage:python3 geolocator.py pcap_file kml_output\n\n   Ex:python3 geolocator.py sample.pcap result.kml\n')
    try:
        pcap_file = sys.argv[1]
        output_file  = sys.argv[2]
    except IndexError:
        print(f'[!]Refer Usage dialog again')
        sys.exit(1)
        
    pcap_obj = []

    if os.path.exists(pcap_file) and pcap_file.endswith('.pcap'):
        print(f'[+] PCAP File found,reading....')
        f = open(pcap_file, 'rb')
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            pcap_obj.append([ts, buf])
        locator(pcap_obj,output_file)
        f.close()
        
    else:
        print(f'[!] file not found, please try again')
        sys.exit(1)


if __name__ == "__main__":
    main()