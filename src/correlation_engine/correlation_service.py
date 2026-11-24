"""Evidence Relations & Correlation Engine using NetworkX.

Strict forensic rule: Only verifiable relationships backed by extracted artifacts
are marked as verified links. Temporal proximity links are explicitly labeled
as unverified hypotheses rather than proven facts.
"""

from typing import Any, Dict, List, Optional
import networkx as nx

from src.database.models import init_db, Case, Evidence, UsbDeviceRecord
from src.database.seed import seed_database_if_empty


class CorrelationService:
    """Builds verifiable forensic entity graphs and computes layout coordinates."""

    def __init__(self, db_path: str = "data/forensics.db"):
        self.db_path = db_path
        self.Session = init_db(db_path)
        seed_database_if_empty(db_path)

    def build_case_graph(self, case_id: Optional[int] = None, include_hypotheses: bool = True) -> Dict[str, Any]:
        """Construct a verifiable graph linking Case, Users, Evidence, and USB Devices."""
        G = nx.Graph()
        nodes_meta: Dict[str, Dict[str, Any]] = {}
        edges_meta: List[Dict[str, Any]] = []

        with self.Session() as s:
            case = s.query(Case).filter(Case.id == case_id).first() if case_id else s.query(Case).first()
            if not case:
                return {"nodes": [], "edges": []}

            case_nid = f"case:{case.id}"
            G.add_node(case_nid)
            nodes_meta[case_nid] = {
                "id": case_nid,
                "label": case.case_number,
                "sublabel": case.title[:28],
                "kind": "Vaka",
                "evidence_source": f"Veritabanı::cases (ID={case.id})",
                "details": f"Vaka: {case.case_number}\nBaşlık: {case.title}\nUzman: {case.investigator}",
            }

            evds = s.query(Evidence).filter(Evidence.case_id == case.id).all()
            evd_by_serial: Dict[str, str] = {}
            for e in evds:
                enid = f"evd:{e.id}"
                G.add_node(enid)
                nodes_meta[enid] = {
                    "id": enid,
                    "label": e.evidence_number,
                    "sublabel": f"{e.brand} {e.model}".strip(),
                    "kind": "Delil",
                    "evidence_source": f"Delil Envanteri (Seri: {e.serial or '-'})",
                    "details": f"Delil No: {e.evidence_number}\nMarka/Model: {e.brand} {e.model}\nSeri: {e.serial}\nSHA-256: {e.sha256_hash or '-'}",
                }
                G.add_edge(case_nid, enid)
                edges_meta.append({
                    "source": case_nid,
                    "target": enid,
                    "relation": "Vaka Delili",
                    "verified": True,
                    "basis": f"Muhafaza Zinciri & Delil Kabul Kaydı ({e.evidence_number})",
                })
                if e.serial:
                    evd_by_serial[e.serial.strip().lower()] = enid

            usbs = s.query(UsbDeviceRecord).filter(UsbDeviceRecord.case_id == case.id).all()
            user_nodes: Dict[str, str] = {}
            for u in usbs:
                unid = f"usb:{u.id}"
                G.add_node(unid)
                nodes_meta[unid] = {
                    "id": unid,
                    "label": f"{u.vendor or 'USB'} ({u.vid}:{u.pid})",
                    "sublabel": u.device_name[:26],
                    "kind": "Şüpheli USB" if u.is_suspicious else "USB Cihazı",
                    "evidence_source": u.registry_source_key or "USBSTOR",
                    "details": (
                        f"Cihaz: {u.device_name}\nVID/PID: {u.vid}/{u.pid}\n"
                        f"Seri No: {u.serial_number}\nSürücü: {u.drive_letter or '-'}\n"
                        f"Kaynak: {u.registry_source_key}"
                    ),
                }

                # Verified link to matching physical Evidence by serial or evidence_id
                matched_evd = f"evd:{u.evidence_id}" if u.evidence_id and f"evd:{u.evidence_id}" in nodes_meta else evd_by_serial.get((u.serial_number or "").lower())
                if matched_evd:
                    G.add_edge(matched_evd, unid)
                    edges_meta.append({
                        "source": matched_evd,
                        "target": unid,
                        "relation": "Seri No Eşleşmesi",
                        "verified": True,
                        "basis": f"Fiziksel delil seri numarası ({u.serial_number}) ile Registry USBSTOR kaydı eşleşti.",
                    })
                else:
                    G.add_edge(case_nid, unid)
                    edges_meta.append({
                        "source": case_nid,
                        "target": unid,
                        "relation": "Kayıt İzi (Fiziksel Delil Yok)",
                        "verified": True,
                        "basis": f"Registry izinden tespit edildi: {u.registry_source_key}",
                    })

                # Link to User Account
                uname = u.user_account or "SYSTEM"
                if uname not in user_nodes:
                    usr_nid = f"user:{len(user_nodes) + 1}"
                    user_nodes[uname] = usr_nid
                    G.add_node(usr_nid)
                    nodes_meta[usr_nid] = {
                        "id": usr_nid,
                        "label": uname,
                        "sublabel": u.user_sid or "Kullanıcı Profili",
                        "kind": "Kullanıcı",
                        "evidence_source": f"SID: {u.user_sid or 'Bilinmiyor'}",
                        "details": f"Kullanıcı: {uname}\nSID: {u.user_sid or '-'}",
                    }
                usr_nid = user_nodes[uname]
                G.add_edge(usr_nid, unid)
                edges_meta.append({
                    "source": usr_nid,
                    "target": unid,
                    "relation": "Profil Bağlantısı (MountPoints2/SID)",
                    "verified": bool(u.user_sid and u.drive_letter),
                    "basis": (
                        f"MountPoints2 ve Kullanıcı SID ({u.user_sid}) eşleşmesi."
                        if (u.user_sid and u.drive_letter)
                        else "⚠️ Yalnız sistem zaman aralığına göre olası ilişki (MountPoints2/harf yok — kesin kanıt değil)."
                    ),
                })

            # Optional temporal correlation hypothesis between suspicious USB and other devices
            if include_hypotheses:
                susp_usbs = [u for u in usbs if u.is_suspicious]
                normal_usbs = [u for u in usbs if not u.is_suspicious]
                for su in susp_usbs:
                    for nu in normal_usbs:
                        if su.first_connected and nu.first_connected:
                            delta_hrs = abs((su.first_connected - nu.first_connected).total_seconds()) / 3600.0
                            if delta_hrs <= 72:
                                s_id, n_id = f"usb:{su.id}", f"usb:{nu.id}"
                                G.add_edge(s_id, n_id)
                                edges_meta.append({
                                    "source": s_id,
                                    "target": n_id,
                                    "relation": "Zamansal Yakınlık (Kanıtlanmamış)",
                                    "verified": False,
                                    "basis": f"⚠️ İki cihaz {delta_hrs:.1f} saat aralığında sisteme bağlandı. Doğrudan nedensellik kanıtlanmamıştır.",
                                })

        # Compute clean deterministic layout via NetworkX spring_layout
        pos = nx.spring_layout(G, seed=42, k=1.4) if len(G.nodes) > 0 else {}
        out_nodes = []
        for nid, meta in nodes_meta.items():
            x, y = pos.get(nid, (0.0, 0.0))
            meta["x"] = float(x)
            meta["y"] = float(y)
            out_nodes.append(meta)

        if not include_hypotheses:
            edges_meta = [e for e in edges_meta if e["verified"]]

        return {"nodes": out_nodes, "edges": edges_meta}
