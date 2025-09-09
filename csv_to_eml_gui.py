import os, csv, pathlib, sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

def _bump_csv_field_limit():
    try:
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        csv.field_size_limit(2**31 - 1)

class EnronCSVtoEMLApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Enron CSV → EML Converter")

        self.csv_file = tk.StringVar()
        self.out_dir  = tk.StringVar()
        self.row_limit_enabled = tk.BooleanVar(value=False)
        self.row_limit_value   = tk.IntVar(value=1000)

        frm = ttk.Frame(root, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frm, text="CSV File:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.csv_file, width=56).grid(row=0, column=1)
        ttk.Button(frm, text="Browse", command=self.browse_csv).grid(row=0, column=2)

        ttk.Label(frm, text="Output Directory:").grid(row=1, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.out_dir, width=56).grid(row=1, column=1)
        ttk.Button(frm, text="Browse", command=self.browse_outdir).grid(row=1, column=2)

        # Row limit (optional) for fast demo runs
        limit_row = ttk.Frame(frm)
        limit_row.grid(row=2, column=0, columnspan=3, sticky="w", pady=(6,0))
        ttk.Checkbutton(limit_row, text="Convert only first", variable=self.row_limit_enabled).grid(row=0, column=0, sticky="w")
        ttk.Spinbox(limit_row, from_=1, to=10_000_000, textvariable=self.row_limit_value, width=8).grid(row=0, column=1, padx=6)
        ttk.Label(limit_row, text="rows").grid(row=0, column=2)

        btns = ttk.Frame(frm)
        btns.grid(row=3, column=0, columnspan=3, pady=8, sticky="e")
        ttk.Button(btns, text="Convert", command=self.convert).grid(row=0, column=0, padx=4)
        ttk.Button(btns, text="Quit", command=root.quit).grid(row=0, column=1, padx=4)

        self.log = tk.Text(frm, height=14, width=80, state="disabled")
        self.log.grid(row=4, column=0, columnspan=3, pady=6)

        # Indeterminate progress bar (no f.tell())
        self.progress = ttk.Progressbar(frm, length=520, mode="indeterminate")
        self.progress.grid(row=5, column=0, columnspan=3, pady=4)

    def browse_csv(self):
        f = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if f:
            self.csv_file.set(f)

    def browse_outdir(self):
        d = filedialog.askdirectory()
        if d:
            self.out_dir.set(d)

    def log_msg(self, msg):
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.config(state="disabled")
        self.root.update_idletasks()

    def convert(self):
        in_csv = self.csv_file.get()
        out_dir = self.out_dir.get()
        col = "message"  # Enron column

        if not in_csv or not out_dir:
            messagebox.showerror("Error", "Please select input CSV and output directory.")
            return

        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Error", f"Cannot create output directory:\n{e}")
            return

        _bump_csv_field_limit()

        wrote = skipped = 0
        row_limit = self.row_limit_value.get() if self.row_limit_enabled.get() else None

        try:
            with open(in_csv, newline="", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)

                # ensure we have a usable column
                if col not in (reader.fieldnames or []):
                    # try common alternatives
                    candidates = [c for c in (reader.fieldnames or []) if c.lower() in ("message","raw","text","content")]
                    if candidates:
                        col = candidates[0]
                        self.log_msg(f"Using detected column: {col}")
                    else:
                        messagebox.showerror("Error", f"Column '{col}' not found. Columns: {reader.fieldnames}")
                        return

                self.progress.start(12)  # start indeterminate bar

                for i, row in enumerate(reader):
                    if row_limit is not None and i >= row_limit:
                        break

                    raw = row.get(col, "") or ""
                    if not (("From:" in raw) and ("Message-ID:" in raw or "Date:" in raw or "Received:" in raw)):
                        skipped += 1
                        if i % 500 == 0:
                            self.root.update_idletasks()
                        continue

                    # ensure blank line between headers/body
                    if "\n\n" not in raw and "\r\n\r\n" not in raw:
                        lines = raw.splitlines()
                        hdr_end_idx = 0
                        for j, line in enumerate(lines):
                            if line.strip() == "":
                                hdr_end_idx = j
                                break
                            if not (":" in line or line.startswith((" ", "\t"))):
                                hdr_end_idx = j
                                break
                        lines.insert(hdr_end_idx, "")
                        raw = "\n".join(lines)

                    out_path = pathlib.Path(out_dir) / f"csvmsg_{i:07d}.eml"
                    with open(out_path, "w", encoding="utf-8", errors="ignore") as o:
                        o.write(raw)
                    wrote += 1

                    if i % 500 == 0:
                        self.log_msg(f"Processed {i+1} rows… (wrote {wrote}, skipped {skipped})")
                        self.root.update_idletasks()

                self.progress.stop()

            self.log_msg(f"Done! Wrote {wrote} .eml files (skipped {skipped}).")
            messagebox.showinfo("Completed", f"Conversion finished!\nWrote {wrote} .eml files.\nSkipped {skipped} rows.")
        except Exception as e:
            self.progress.stop()
            messagebox.showerror("Error", f"Conversion failed: {e}")

def main():
    root = tk.Tk()
    app = EnronCSVtoEMLApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
