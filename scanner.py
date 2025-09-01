import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import ARP, Ether, srp
from manuf import manuf
import socket

# MAC vendor resolver
p = manuf.MacParser()

def guess_os(ttl):
    if ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux / Android"
    elif ttl >= 255:
        return "Cisco / Network Device"
    else:
        return "Unknown"

def scan_network(subnet):
    devices = []
    try:
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=2, verbose=0)[0]

        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc
            vendor = p.get_manuf(mac) or "Unknown"

            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"

            # Basit TTL ile OS tahmini
            ttl_guess = "Unknown"
            try:
                ttl = received.ttl
                ttl_guess = guess_os(ttl)
            except:
                pass

            devices.append((ip, mac, vendor, hostname, ttl_guess))

    except Exception as e:
        messagebox.showerror("Hata", f"Ağ taraması sırasında hata oluştu:\n{e}")

    return devices

def start_scan():
    subnet = entry_subnet.get().strip()
    if not subnet:
        messagebox.showwarning("Uyarı", "Lütfen bir subnet giriniz! (örn: 192.168.1.0/24)")
        return

    devices = scan_network(subnet)
    tree.delete(*tree.get_children())

    for device in devices:
        tree.insert("", "end", values=device)

    lbl_status.config(text=f"{len(devices)} cihaz bulundu.")

# GUI
root = tk.Tk()
root.title("Network Scanner")

frame = tk.Frame(root)
frame.pack(pady=10)

lbl = tk.Label(frame, text="Subnet (örn: 192.168.1.0/24):")
lbl.grid(row=0, column=0, padx=5)

entry_subnet = tk.Entry(frame, width=20)
entry_subnet.grid(row=0, column=1, padx=5)
entry_subnet.insert(0, "192.168.1.0/24")

btn = tk.Button(frame, text="Tara", command=start_scan)
btn.grid(row=0, column=2, padx=5)

columns = ("IP", "MAC", "Vendor", "Hostname", "OS Guess")
tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)
tree.pack(fill="both", expand=True)

lbl_status = tk.Label(root, text="")
lbl_status.pack(pady=5)

root.mainloop()
