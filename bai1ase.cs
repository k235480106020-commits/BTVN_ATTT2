#nullable disable
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Drawing;
using System.Windows.Forms;
using Application = System.Windows.Forms.Application;
using Label = System.Windows.Forms.Label;
using Font = System.Drawing.Font;

namespace Bai1Aes;

// =====================================================================
//  PHẦN LÕI MẬT MÃ (không phụ thuộc giao diện)
// =====================================================================
public static class Engine
{
    public const int Buf = 4 * 1024 * 1024; // 4 MB mỗi lần đọc/ghi

    // ------------------------- AES -------------------------
    public static byte[] NewAesKey()
    {
        using var a = Aes.Create();
        a.KeySize = 256;
        a.GenerateKey();
        return a.Key;
    }

    public static byte[] ParseKey(string base64)
    {
        byte[] k = Convert.FromBase64String(base64.Trim());
        if (k.Length != 16 && k.Length != 24 && k.Length != 32)
            throw new InvalidDataException("Độ dài khoá không hợp lệ (phải 16, 24 hoặc 32 byte).");
        return k;
    }

    // Đầu ra: Base64( IV(16) || Ciphertext )
    public static string EncryptText(string text, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        byte[] cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(text), aes.IV, PaddingMode.PKCS7);
        byte[] all = new byte[16 + cipher.Length];
        Buffer.BlockCopy(aes.IV, 0, all, 0, 16);
        Buffer.BlockCopy(cipher, 0, all, 16, cipher.Length);
        return Convert.ToBase64String(all);
    }

    public static string DecryptText(string base64, byte[] key)
    {
        byte[] all = Convert.FromBase64String(base64.Trim());
        if (all.Length < 32) throw new InvalidDataException("Chuỗi Base64 quá ngắn, không phải bản mã hợp lệ.");
        using var aes = Aes.Create();
        aes.Key = key;
        byte[] plain = aes.DecryptCbc(all[16..], all[..16], PaddingMode.PKCS7);
        return Encoding.UTF8.GetString(plain);
    }

    // File: IV(16) || Ciphertext, xử lý theo luồng nên chạy được file hàng GB
    public static void EncryptFile(string src, string dst, byte[] key, IProgress<double> prog = null)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, Buf);
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, Buf);
        fout.Write(aes.IV, 0, 16);
        using var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write);
        byte[] buf = new byte[Buf];
        long total = fin.Length, done = 0;
        int n;
        while ((n = fin.Read(buf, 0, buf.Length)) > 0)
        {
            cs.Write(buf, 0, n);
            done += n;
            prog?.Report(total == 0 ? 1 : (double)done / total);
        }
        cs.FlushFinalBlock();
    }

    public static void DecryptFile(string src, string dst, byte[] key, IProgress<double> prog = null)
    {
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, Buf);
        byte[] iv = new byte[16];
        fin.ReadExactly(iv, 0, 16);
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, Buf);
        using var cs = new CryptoStream(fin, aes.CreateDecryptor(), CryptoStreamMode.Read);
        byte[] buf = new byte[Buf];
        int n;
        while ((n = cs.Read(buf, 0, buf.Length)) > 0)
        {
            fout.Write(buf, 0, n);
            prog?.Report(fin.Length == 0 ? 1 : (double)fin.Position / fin.Length);
        }
    }

    public static void CreateRandomFile(string path, long sizeMb, IProgress<double> prog = null)
    {
        byte[] buf = new byte[1024 * 1024];
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, Buf);
        for (long i = 0; i < sizeMb; i++)
        {
            RandomNumberGenerator.Fill(buf);
            fs.Write(buf, 0, buf.Length);
            prog?.Report((double)(i + 1) / sizeMb);
        }
    }

    // -1 nếu giống hệt, ngược lại là vị trí byte khác nhau đầu tiên
    public static long CompareFiles(string a, string b, IProgress<double> prog = null)
    {
        using var fa = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.Read, Buf);
        using var fb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.Read, Buf);
        if (fa.Length != fb.Length) return Math.Min(fa.Length, fb.Length);
        byte[] ba = new byte[Buf], bb = new byte[Buf];
        long pos = 0;
        while (true)
        {
            int na = ReadFull(fa, ba), nb = ReadFull(fb, bb);
            if (na != nb) return pos;
            if (na == 0) return -1;
            if (!ba.AsSpan(0, na).SequenceEqual(bb.AsSpan(0, nb)))
                for (int i = 0; i < na; i++) if (ba[i] != bb[i]) return pos + i;
            pos += na;
            prog?.Report(fa.Length == 0 ? 1 : (double)pos / fa.Length);
        }
    }

    static int ReadFull(Stream s, byte[] buf)
    {
        int total = 0;
        while (total < buf.Length)
        {
            int n = s.Read(buf, total, buf.Length - total);
            if (n == 0) break;
            total += n;
        }
        return total;
    }

}
// ===== HẾT PHẦN LÕI =====

// =====================================================================
//  GIAO DIỆN (WinForms) - toàn bộ dựng bằng code, không cần file Designer
// =====================================================================
static class State
{
    public static byte[] AesKey;
    public static event Action KeyChanged;
    public static void SetKey(byte[] k) { AesKey = k; KeyChanged?.Invoke(); }
}

static class UI
{
    public static float Scale = 1f;
    public static Action<string> Status = _ => { };
    public static int H(int v) => (int)Math.Round(v * Scale);

    public static readonly Color Bg = Color.FromArgb(241, 245, 249);
    public static readonly Color Side = Color.FromArgb(30, 58, 138);
    public static readonly Color Accent = Color.FromArgb(37, 99, 235);
    public static readonly Color AccentDark = Color.FromArgb(29, 78, 216);
    public static readonly Color Ink = Color.FromArgb(15, 23, 42);
    public static readonly Color Muted = Color.FromArgb(100, 116, 139);
    public static readonly Color Border = Color.FromArgb(226, 232, 240);
    public static readonly Color Soft = Color.FromArgb(248, 250, 252);
    public static readonly Color Ok = Color.FromArgb(22, 163, 74);
    public static readonly Color Bad = Color.FromArgb(220, 38, 38);

    public static Font Fnt(float pt, FontStyle st = FontStyle.Regular) => new Font("Segoe UI", pt, st);

    public static void Round(Control c, int r)
    {
        if (c.Width <= 0 || c.Height <= 0) return;
        using var p = new System.Drawing.Drawing2D.GraphicsPath();
        int d = r * 2;
        p.AddArc(0, 0, d, d, 180, 90);
        p.AddArc(c.Width - d, 0, d, d, 270, 90);
        p.AddArc(c.Width - d, c.Height - d, d, d, 0, 90);
        p.AddArc(0, c.Height - d, d, d, 90, 90);
        p.CloseFigure();
        c.Region = new Region(p);
    }

    public static Button Btn(string text, EventHandler click, bool primary = true)
    {
        var b = new Button
        {
            Text = text, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand, Font = Fnt(10, FontStyle.Bold),
            Padding = new Padding(H(10), H(3), H(10), H(3)), Margin = new Padding(0, 0, H(10), 0),
            MinimumSize = new Size(0, H(36)), UseVisualStyleBackColor = false,
            BackColor = primary ? Accent : Color.White, ForeColor = primary ? Color.White : Accent
        };
        b.FlatAppearance.BorderSize = primary ? 0 : 1;
        b.FlatAppearance.BorderColor = Accent;
        b.FlatAppearance.MouseOverBackColor = primary ? AccentDark : Color.FromArgb(239, 246, 255);
        b.SizeChanged += (s, e) => Round(b, H(8));
        b.Click += click;
        return b;
    }

    public static Label Lbl(string text, bool bold = false, bool muted = false, int h = 26)
    {
        return new Label
        {
            Text = text, AutoSize = false, Height = H(h), Margin = Padding.Empty,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = Fnt(10, bold ? FontStyle.Bold : FontStyle.Regular),
            ForeColor = muted ? Muted : Ink
        };
    }

    public static Label Note(string text, int h) => new Label
    {
        Text = text, AutoSize = false, Height = H(h), Margin = Padding.Empty,
        TextAlign = ContentAlignment.TopLeft, Font = Fnt(9.5f), ForeColor = Muted
    };

    public static TextBox Txt(bool ro = false, bool mono = false, bool multi = false, string text = "")
    {
        var t = new TextBox
        {
            BorderStyle = BorderStyle.FixedSingle, ReadOnly = ro, Multiline = multi, Text = text,
            Font = mono ? new Font("Consolas", 10f) : Fnt(10),
            BackColor = ro ? Soft : Color.White, ForeColor = Ink
        };
        if (multi) t.ScrollBars = ScrollBars.Vertical;
        return t;
    }

    public static Control Field(string label, Control input, Button extra = null, int h = 42)
    {
        var t = new TableLayoutPanel
        {
            Height = H(h), ColumnCount = 3, RowCount = 1, Margin = Padding.Empty, BackColor = Color.Transparent
        };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, H(160)));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        t.Controls.Add(new Label
        {
            Text = label, AutoSize = false, Dock = DockStyle.Fill, Margin = Padding.Empty,
            TextAlign = ContentAlignment.MiddleLeft, ForeColor = Ink, Font = Fnt(10)
        }, 0, 0);
        bool narrow = input is NumericUpDown || input is ComboBox;
        input.Anchor = narrow ? AnchorStyles.Left : AnchorStyles.Left | AnchorStyles.Right;
        input.Margin = new Padding(0, H(4), H(10), H(4));
        t.Controls.Add(input, 1, 0);
        if (extra != null)
        {
            extra.Anchor = AnchorStyles.Left;
            extra.Margin = Padding.Empty;
            t.Controls.Add(extra, 2, 0);
        }
        return t;
    }

    public static FlowLayoutPanel Flow(params Control[] cs)
    {
        var f = new FlowLayoutPanel
        {
            Height = H(48), WrapContents = false, FlowDirection = FlowDirection.LeftToRight,
            Margin = Padding.Empty, Padding = new Padding(0, H(6), 0, 0), BackColor = Color.Transparent
        };
        f.Controls.AddRange(cs);
        return f;
    }

    public static FlowLayoutPanel Flow2(params Control[] cs)
    {
        var f = new FlowLayoutPanel { Height = H(30), WrapContents = false, FlowDirection = FlowDirection.LeftToRight, Margin = Padding.Empty, BackColor = Color.Transparent };
        f.Controls.AddRange(cs);
        return f;
    }

    public static ProgressBar Bar() => new ProgressBar { Minimum = 0, Maximum = 100, Height = H(18), Margin = Padding.Empty };

    public static DataGridView Grid(params string[] cols)
    {
        var g = new DataGridView
        {
            ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false, AllowUserToResizeRows = false,
            RowHeadersVisible = false, BackgroundColor = Color.White, BorderStyle = BorderStyle.None,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            EnableHeadersVisualStyles = false, GridColor = Border,
            CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal,
            ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing,
            ColumnHeadersHeight = H(34), Font = Fnt(9.5f), Margin = Padding.Empty
        };
        g.RowTemplate.Height = H(30);
        g.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(239, 246, 255);
        g.ColumnHeadersDefaultCellStyle.ForeColor = AccentDark;
        g.ColumnHeadersDefaultCellStyle.Font = Fnt(9.5f, FontStyle.Bold);
        g.ColumnHeadersDefaultCellStyle.SelectionBackColor = Color.FromArgb(239, 246, 255);
        g.ColumnHeadersDefaultCellStyle.SelectionForeColor = AccentDark;
        g.DefaultCellStyle.SelectionBackColor = Color.FromArgb(219, 234, 254);
        g.DefaultCellStyle.SelectionForeColor = Ink;
        foreach (string c in cols) g.Columns.Add(c, c);
        return g;
    }

    public static string OpenFile(string filter = "Tất cả tệp|*.*")
    {
        using var d = new OpenFileDialog { Filter = filter };
        return d.ShowDialog() == DialogResult.OK ? d.FileName : null;
    }

    public static string SaveFile(string name, string filter = "Tất cả tệp|*.*")
    {
        using var d = new SaveFileDialog { FileName = name, Filter = filter };
        return d.ShowDialog() == DialogResult.OK ? d.FileName : null;
    }

    public static string PickFolder(string start)
    {
        using var d = new FolderBrowserDialog { SelectedPath = start };
        return d.ShowDialog() == DialogResult.OK ? d.SelectedPath : null;
    }

    public static void Error(Exception ex)
    {
        MessageBox.Show(ex.Message, "Có lỗi xảy ra", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        Status("Lỗi: " + ex.Message);
    }

    public static bool NeedKey()
    {
        if (State.AesKey != null) return true;
        MessageBox.Show("Chưa có khoá AES. Hãy vào mục «Khoá AES» để sinh khoá hoặc nạp khoá từ file.",
            "Thiếu khoá", MessageBoxButtons.OK, MessageBoxIcon.Information);
        return false;
    }
}


// Ngăn xếp dọc: mỗi control chiếm 1 hàng (cố định chiều cao, hoặc chiếm phần còn lại)
class VStack : TableLayoutPanel
{
    int rows;
    public int Total;

    public VStack()
    {
        Dock = DockStyle.Fill;
        ColumnCount = 1;
        ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        Margin = Padding.Empty;
        BackColor = Color.Transparent;
    }

    public T Add<T>(T c) where T : Control
    {
        if (c is Card cd && !cd.IsFill) cd.Seal();
        int h = c.Height + c.Margin.Vertical;
        RowStyles.Add(new RowStyle(SizeType.Absolute, h));
        Total += h;
        Place(c);
        return c;
    }

    public T Fill<T>(T c) where T : Control
    {
        RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        Place(c);
        return c;
    }

    void Place(Control c)
    {
        c.Dock = DockStyle.Fill;
        RowCount = rows + 1;
        Controls.Add(c, 0, rows);
        rows++;
    }
}

// Thẻ trắng có viền, có tiêu đề
class Card : VStack
{
    public readonly bool IsFill;

    public Card(string title, bool fill = false)
    {
        IsFill = fill;
        BackColor = Color.White;
        Padding = new Padding(UI.H(18), UI.H(12), UI.H(18), UI.H(12));
        Margin = new Padding(0, 0, 0, UI.H(14));
        var t = UI.Lbl(title, bold: true, h: 32);
        t.Font = UI.Fnt(11.5f, FontStyle.Bold);
        t.ForeColor = UI.Accent;
        Add(t);
    }

    public void Seal() { Height = Total + Padding.Vertical; }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        using var p = new Pen(UI.Border);
        e.Graphics.DrawRectangle(p, 0, 0, Width - 1, Height - 1);
    }
}


// =====================================================================
//  CÁC TRANG CỦA BÀI 1
// =====================================================================
static class Pages
{
    // ---------------- BÀI 1 / Khoá AES ----------------
    public static Control AesKey()
    {
        var page = new VStack();
        var card = new Card("Khoá AES-256");
        card.Add(UI.Note("AES là mã hoá đối xứng: mã hoá và giải mã dùng chung MỘT khoá 256 bit (32 byte). Khoá hiển thị ở dạng Base64; hãy giữ file khoá bí mật.", 44));
        var tb = UI.Txt(ro: true, mono: true);
        card.Add(UI.Field("Khoá (Base64)", tb));
        var info = UI.Lbl("Trạng thái: chưa có khoá", muted: true);
        card.Add(info);

        void Refresh()
        {
            if (State.AesKey == null) { tb.Text = ""; info.Text = "Trạng thái: chưa có khoá"; return; }
            tb.Text = Convert.ToBase64String(State.AesKey);
            info.Text = $"Trạng thái: đã có khoá {State.AesKey.Length * 8} bit ({State.AesKey.Length} byte)";
        }
        State.KeyChanged += Refresh;

        card.Add(UI.Flow(
            UI.Btn("Sinh khoá mới", (s, e) => { State.SetKey(Engine.NewAesKey()); UI.Status("Đã sinh khoá AES-256 mới."); }),
            UI.Btn("Lưu khoá ra file...", (s, e) =>
            {
                try
                {
                    if (!UI.NeedKey()) return;
                    string p = UI.SaveFile("aes.key", "Khoá AES|*.key|Tất cả tệp|*.*");
                    if (p == null) return;
                    File.WriteAllText(p, Convert.ToBase64String(State.AesKey));
                    UI.Status("Đã lưu khoá vào: " + p);
                }
                catch (Exception ex) { UI.Error(ex); }
            }, false),
            UI.Btn("Nạp khoá từ file...", (s, e) =>
            {
                try
                {
                    string p = UI.OpenFile("Khoá AES|*.key|Tất cả tệp|*.*");
                    if (p == null) return;
                    State.SetKey(Engine.ParseKey(File.ReadAllText(p)));
                    UI.Status("Đã nạp khoá từ: " + p);
                }
                catch (Exception ex) { UI.Error(ex); }
            }, false)));
        page.Add(card);

        var guide = new Card("Chế độ mã hoá sử dụng");
        guide.Add(UI.Note("AES-256-CBC + PKCS7. Mỗi lần mã hoá tạo một IV (16 byte) ngẫu nhiên và ghi ở đầu kết quả:  [ IV 16 byte ][ Bản mã ].\r\nNhờ IV ngẫu nhiên, cùng một nội dung mã hoá hai lần sẽ cho hai kết quả khác nhau. Bản mã dài hơn bản rõ từ 17 đến 32 byte.", 70));
        page.Add(guide);
        Refresh();
        return page;
    }

    // ---------------- BÀI 1 / Văn bản ----------------
    public static Control AesText()
    {
        var page = new VStack();
        var card = new Card("Mã hoá / giải mã văn bản", true);
        card.Add(UI.Note("Mã hoá: nhập văn bản, bấm «Mã hoá» để nhận chuỗi Base64. Giải mã: dán chuỗi Base64 vào ô «Đầu vào», bấm «Giải mã».", 44));
        card.Add(UI.Lbl("Đầu vào", bold: true));
        var tin = UI.Txt(multi: true);
        card.Fill(tin);
        var tout = UI.Txt(multi: true, ro: true, mono: true);
        card.Add(UI.Flow(
            UI.Btn("Mã hoá", (s, e) =>
            {
                try { if (!UI.NeedKey()) return; tout.Text = Engine.EncryptText(tin.Text, State.AesKey); UI.Status("Đã mã hoá văn bản."); }
                catch (Exception ex) { UI.Error(ex); }
            }),
            UI.Btn("Giải mã", (s, e) =>
            {
                try { if (!UI.NeedKey()) return; tout.Text = Engine.DecryptText(tin.Text, State.AesKey); UI.Status("Đã giải mã văn bản."); }
                catch (Exception ex) { UI.Error(new Exception("Không giải mã được (sai khoá hoặc chuỗi Base64 không hợp lệ).\r\n" + ex.Message)); }
            }, false),
            UI.Btn("Xoá", (s, e) => { tin.Clear(); tout.Clear(); }, false)));
        card.Add(UI.Lbl("Kết quả", bold: true));
        card.Fill(tout);
        page.Fill(card);
        return page;
    }

    // ---------------- BÀI 1 / Mã hoá file ----------------
    public static Control AesFile()
    {
        var page = new VStack();
        var card = new Card("Mã hoá / giải mã file (xử lý theo luồng, file hàng GB không tốn RAM)", true);
        var src = UI.Txt();
        var dst = UI.Txt();
        card.Add(UI.Field("File nguồn", src, UI.Btn("Chọn...", (s, e) =>
        {
            string p = UI.OpenFile();
            if (p != null) { src.Text = p; dst.Text = ""; }
        }, false)));
        card.Add(UI.Field("File đích", dst, UI.Btn("Chọn...", (s, e) =>
        {
            string p = UI.SaveFile(Path.GetFileName(dst.Text));
            if (p != null) dst.Text = p;
        }, false)));
        var bar = UI.Bar();
        var log = UI.Txt(multi: true, ro: true, mono: true);
        var bEnc = UI.Btn("Mã hoá file", null);
        var bDec = UI.Btn("Giải mã file", null, false);

        async Task Do(bool enc)
        {
            try
            {
                if (!UI.NeedKey()) return;
                if (!File.Exists(src.Text)) throw new FileNotFoundException("Chưa chọn file nguồn hợp lệ.");
                if (dst.Text.Length == 0)
                    dst.Text = enc ? src.Text + ".enc" : (src.Text.EndsWith(".enc") ? src.Text[..^4] + ".dec" : src.Text + ".dec");
                bEnc.Enabled = bDec.Enabled = false;
                bar.Value = 0;
                var prog = new Progress<double>(v => bar.Value = Math.Min(100, (int)(v * 100)));
                string a = src.Text, b = dst.Text;
                byte[] key = State.AesKey;
                UI.Status(enc ? "Đang mã hoá..." : "Đang giải mã...");
                var sw = Stopwatch.StartNew();
                await Task.Run(() => { if (enc) Engine.EncryptFile(a, b, key, prog); else Engine.DecryptFile(a, b, key, prog); });
                sw.Stop();
                bar.Value = 100;
                double mb = new FileInfo(a).Length / 1048576.0;
                log.AppendText($"{(enc ? "MÃ HOÁ" : "GIẢI MÃ")}  {Path.GetFileName(a)} -> {b}\r\n" +
                               $"   Dung lượng nguồn: {mb:F1} MB   Thời gian: {sw.Elapsed.TotalSeconds:F3} s   Tốc độ: {mb / Math.Max(sw.Elapsed.TotalSeconds, 1e-6):F1} MB/s\r\n");
                UI.Status("Hoàn tất.");
                dst.Text = "";
            }
            catch (Exception ex) { UI.Error(ex); }
            finally { bEnc.Enabled = bDec.Enabled = true; }
        }
        bEnc.Click += async (s, e) => await Do(true);
        bDec.Click += async (s, e) => await Do(false);
        card.Add(UI.Flow(bEnc, bDec));
        card.Add(bar);
        card.Add(UI.Lbl("Nhật ký", bold: true));
        card.Fill(log);
        page.Fill(card);
        return page;
    }

    // ---------------- BÀI 1 / Thử nghiệm file lớn ----------------
    public static Control AesBench()
    {
        var page = new VStack();
        var card = new Card("Thử nghiệm file lớn: tạo file, mã hoá, giải mã, đo thời gian, so sánh từng byte", true);
        var nud = new NumericUpDown { Minimum = 1, Maximum = 65536, Value = 1024, Width = UI.H(140), ThousandsSeparator = true, Font = UI.Fnt(10) };
        card.Add(UI.Field("Dung lượng (MB)", nud));
        var dir = UI.Txt(text: Path.GetTempPath());
        card.Add(UI.Field("Thư mục thử nghiệm", dir, UI.Btn("Chọn...", (s, e) =>
        {
            string p = UI.PickFolder(dir.Text);
            if (p != null) dir.Text = p;
        }, false)));
        var chk = new CheckBox { Text = "Xoá file tạm sau khi thử", Checked = true, AutoSize = true, Font = UI.Fnt(10), Margin = new Padding(UI.H(6), UI.H(8), 0, 0) };
        var bar = UI.Bar();
        var stage = UI.Lbl("Sẵn sàng. Mỗi lần thử cần trống khoảng 3 lần dung lượng file.", muted: true);
        var grid = UI.Grid("Dung lượng", "Mã hoá (s)", "MB/s mã hoá", "Giải mã (s)", "MB/s giải mã", "So sánh byte");
        var concl = UI.Txt(multi: true, ro: true);
        var results = new List<(double mb, double te, double td)>();
        var run = UI.Btn("Chạy thử nghiệm", null);

        run.Click += async (s, e) =>
        {
            try
            {
                if (!UI.NeedKey()) { return; }
                run.Enabled = false;
                long mb = (long)nud.Value;
                Directory.CreateDirectory(dir.Text);
                string src = Path.Combine(dir.Text, "aes_test_src.bin"), enc = src + ".enc", dec = src + ".dec";
                byte[] key = State.AesKey;
                var prog = new Progress<double>(v => bar.Value = Math.Min(100, (int)(v * 100)));

                async Task<double> Stage(string name, Action work)
                {
                    stage.Text = name; bar.Value = 0; UI.Status(name);
                    var sw = Stopwatch.StartNew();
                    await Task.Run(work);
                    sw.Stop();
                    bar.Value = 100;
                    return sw.Elapsed.TotalSeconds;
                }

                await Stage($"[1/4] Tạo file ngẫu nhiên {mb:N0} MB...", () => Engine.CreateRandomFile(src, mb, prog));
                double te = await Stage("[2/4] Đang mã hoá...", () => Engine.EncryptFile(src, enc, key, prog));
                double td = await Stage("[3/4] Đang giải mã...", () => Engine.DecryptFile(enc, dec, key, prog));
                long diff = -1;
                await Stage("[4/4] So sánh từng byte file nguồn và file giải mã...", () => diff = Engine.CompareFiles(src, dec, prog));

                double size = new FileInfo(src).Length / 1048576.0;
                long encSize = new FileInfo(enc).Length, srcSize = new FileInfo(src).Length;
                string cmp = diff < 0 ? "GIỐNG HỆT (0 byte lệch)" : $"KHÁC tại byte {diff:N0}";
                int r = grid.Rows.Add($"{size:N0} MB", te.ToString("F3"), (size / te).ToString("F1"), td.ToString("F3"), (size / td).ToString("F1"), cmp);
                grid.Rows[r].Cells[5].Style.ForeColor = diff < 0 ? UI.Ok : UI.Bad;
                results.Add((size, te, td));

                var sb = new System.Text.StringBuilder();
                sb.AppendLine(diff < 0
                    ? "• File giải mã trùng khớp 100% từng byte với file nguồn: mã hoá/giải mã không làm mất hay sai dữ liệu."
                    : $"• CẢNH BÁO: file giải mã khác file nguồn tại byte {diff:N0}.");
                sb.AppendLine($"• File mã hoá lớn hơn bản gốc {encSize - srcSize} byte (16 byte IV + padding), không đáng kể.");
                sb.AppendLine($"• Mã hoá {size / te:F1} MB/s, giải mã {size / td:F1} MB/s: giải mã {(td < te ? "nhanh hơn" : "chậm hơn")} mã hoá {Math.Max(te / td, td / te):F2} lần" +
                              " (CBC mã hoá phải tuần tự, giải mã có thể song song).");
                if (results.Count >= 2)
                {
                    var f = results[0]; var l = results[^1];
                    if (Math.Abs(l.mb - f.mb) > 1)
                        sb.AppendLine($"• Dung lượng tăng {l.mb / f.mb:F1} lần thì thời gian mã hoá tăng {l.te / f.te:F1} lần, giải mã tăng {l.td / f.td:F1} lần: thời gian tăng gần tuyến tính theo dung lượng.");
                }
                sb.Append("• Bộ nhớ sử dụng gần như không đổi nhờ xử lý theo luồng 4 MB.");
                concl.Text = sb.ToString().Replace("\r\n", "\n").Replace("\n", "\r\n");

                if (chk.Checked) { File.Delete(src); File.Delete(enc); File.Delete(dec); }
                stage.Text = "Hoàn tất.";
                UI.Status("Thử nghiệm hoàn tất.");
            }
            catch (Exception ex) { UI.Error(ex); stage.Text = "Có lỗi."; }
            finally { run.Enabled = true; }
        };
        card.Add(UI.Flow(run, chk));
        card.Add(bar);
        card.Add(stage);
        card.Fill(grid);
        card.Add(UI.Lbl("Kết luận tự động từ số liệu", bold: true));
        var wrap = new Panel { Height = UI.H(120), Margin = new Padding(0, 0, 0, 0) };
        concl.Dock = DockStyle.Fill;
        wrap.Controls.Add(concl);
        card.Add(wrap);
        page.Fill(card);
        return page;
    }
}

// =====================================================================
//  CỬA SỔ CHÍNH
// =====================================================================
class MainForm : Form
{
    readonly Panel host = new Panel { Dock = DockStyle.Fill, BackColor = Color.Transparent };
    readonly Label title = new Label { AutoSize = false, UseMnemonic = false };
    readonly Label sub = new Label { AutoSize = false, UseMnemonic = false };
    readonly Label status = new Label { AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
    readonly List<Button> navButtons = new();
    readonly Dictionary<int, Control> cache = new();
    readonly List<(string title, string sub, Func<Control> make)> items = new();

    public MainForm()
    {
        Text = "Bài 1 - Mã hoá AES";
        Font = UI.Fnt(10);
        BackColor = UI.Bg;
        var wa = Screen.PrimaryScreen.WorkingArea;
        ClientSize = new Size(Math.Min(UI.H(1260), (int)(wa.Width * 0.95)), Math.Min(UI.H(840), (int)(wa.Height * 0.90)));
        MinimumSize = new Size(Math.Min(UI.H(1100), wa.Width), Math.Min(UI.H(740), wa.Height));
        StartPosition = FormStartPosition.CenterScreen;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty, Padding = Padding.Empty };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, UI.H(260)));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        Controls.Add(root);

        // ----- thanh bên -----
        var nav = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, BackColor = UI.Side, FlowDirection = FlowDirection.TopDown,
            WrapContents = false, Margin = Padding.Empty, Padding = Padding.Empty
        };
        nav.Controls.Add(new Label
        {
            Text = "BÀI 1\r\nMÃ HOÁ AES", AutoSize = false, Width = UI.H(260), Height = UI.H(96),
            ForeColor = Color.White, Font = UI.Fnt(13, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(UI.H(22), 0, 0, 0), Margin = Padding.Empty
        });

        void Group(string text) => nav.Controls.Add(new Label
        {
            Text = text, AutoSize = false, Width = UI.H(260), Height = UI.H(40),
            ForeColor = Color.FromArgb(165, 180, 252), Font = UI.Fnt(9, FontStyle.Bold),
            TextAlign = ContentAlignment.BottomLeft, Padding = new Padding(UI.H(22), 0, 0, UI.H(6)), Margin = Padding.Empty
        });

        void Item(string t, string s, Func<Control> make)
        {
            int idx = items.Count;
            items.Add((t, s, make));
            var b = new Button
            {
                Text = t, Width = UI.H(260), Height = UI.H(44), FlatStyle = FlatStyle.Flat, TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(UI.H(22), 0, 0, 0), Margin = Padding.Empty, ForeColor = Color.White,
                BackColor = UI.Side, Font = UI.Fnt(10.5f), Cursor = Cursors.Hand, UseVisualStyleBackColor = false
            };
            b.FlatAppearance.BorderSize = 0;
            b.FlatAppearance.MouseOverBackColor = UI.AccentDark;
            b.Click += (s2, e2) => Show(idx);
            navButtons.Add(b);
            nav.Controls.Add(b);
        }

        Group("MÃ HOÁ AES (ĐỐI XỨNG)");
        Item("Khoá AES", "Sinh khoá, lưu ra file, nạp khoá từ file", Pages.AesKey);
        Item("Mã hoá văn bản", "Mã hoá / giải mã đoạn văn bản, kết quả Base64", Pages.AesText);
        Item("Mã hoá file", "Mã hoá / giải mã file theo luồng", Pages.AesFile);
        Item("Thử nghiệm file lớn", "Đo thời gian, so sánh từng byte, kết luận", Pages.AesBench);
        root.Controls.Add(nav, 0, 0);

        // ----- khu nội dung -----
        var content = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Margin = Padding.Empty,
            Padding = new Padding(UI.H(28), UI.H(20), UI.H(28), UI.H(6)), BackColor = UI.Bg
        };
        content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        content.RowStyles.Add(new RowStyle(SizeType.Absolute, UI.H(80)));
        content.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        content.RowStyles.Add(new RowStyle(SizeType.Absolute, UI.H(30)));

        title.Font = UI.Fnt(20, FontStyle.Bold);
        title.ForeColor = UI.Ink;
        sub.Font = UI.Fnt(10.5f);
        sub.ForeColor = UI.Muted;
        var head = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty, BackColor = Color.Transparent };
        head.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        head.RowStyles.Add(new RowStyle(SizeType.Absolute, UI.H(46)));
        head.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        title.Dock = DockStyle.Fill;
        title.TextAlign = ContentAlignment.MiddleLeft;
        sub.TextAlign = ContentAlignment.TopLeft;
        head.Controls.Add(title, 0, 0);
        head.Controls.Add(sub, 0, 1);
        content.Controls.Add(head, 0, 0);
        content.Controls.Add(host, 0, 1);

        status.Font = UI.Fnt(9);
        status.ForeColor = UI.Muted;
        status.Text = "Sẵn sàng.";
        content.Controls.Add(status, 0, 2);
        root.Controls.Add(content, 1, 0);

        UI.Status = s => { status.Text = s; };
        Show(0);
    }

    void Show(int idx)
    {
        for (int i = 0; i < navButtons.Count; i++)
            navButtons[i].BackColor = i == idx ? UI.Accent : UI.Side;
        title.Text = items[idx].title;
        sub.Text = items[idx].sub;
        if (!cache.ContainsKey(idx)) cache[idx] = items[idx].make();
        host.SuspendLayout();
        host.Controls.Clear();
        cache[idx].Dock = DockStyle.Fill;
        host.Controls.Add(cache[idx]);
        host.ResumeLayout(true);
    }
}

static class Program
{
    [STAThread]
    static void Main()
    {
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        using (var g = Graphics.FromHwnd(IntPtr.Zero)) UI.Scale = g.DpiX / 96f;
        Application.Run(new MainForm());
    }
}

