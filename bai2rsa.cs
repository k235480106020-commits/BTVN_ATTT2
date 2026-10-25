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

namespace Bai2Rsa;

public record SigRow(string Method, int Idx, string Sig, bool Ok);

// =====================================================================
//  PHẦN LÕI MẬT MÃ (không phụ thuộc giao diện)
// =====================================================================
public static class Engine
{
    // ------------------------- RSA / PEM -------------------------
    public static readonly RSAEncryptionPadding Oaep = RSAEncryptionPadding.OaepSHA256; // tối đa 190 byte với khoá 2048 bit

    public static RSA LoadPem(string pemText)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pemText);
        return rsa;
    }

    public static bool IsPrivatePem(string pem) => pem.Contains("PRIVATE KEY");

    public static string KindOfPem(string pem)
    {
        if (pem.Contains("BEGIN RSA PRIVATE KEY")) return "Khoá BÍ MẬT (private) - định dạng PKCS#1";
        if (pem.Contains("BEGIN PRIVATE KEY")) return "Khoá BÍ MẬT (private) - định dạng PKCS#8";
        if (pem.Contains("BEGIN RSA PUBLIC KEY")) return "Khoá CÔNG KHAI (public) - định dạng PKCS#1";
        if (pem.Contains("BEGIN PUBLIC KEY")) return "Khoá CÔNG KHAI (public) - định dạng SubjectPublicKeyInfo (X.509)";
        return "Không nhận dạng được";
    }

    public static string Wrap(string s, int w = 64)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < s.Length; i += w) sb.AppendLine(s.Substring(i, Math.Min(w, s.Length - i)));
        return sb.ToString().TrimEnd();
    }

    static BigInteger Big(byte[] b) => new BigInteger(b, isUnsigned: true, isBigEndian: true);
    static string Spaced(byte[] b) => string.Join(" ", b.Select(x => x.ToString("X2")));

    static byte[] PemToDer(string pem)
    {
        var sb = new StringBuilder();
        foreach (string line in pem.Replace("\r", "").Split('\n'))
        {
            string l = line.Trim();
            if (l.Length == 0 || l.StartsWith("-----")) continue;
            sb.Append(l);
        }
        return Convert.FromBase64String(sb.ToString());
    }

    public static string PemParams(RSA rsa, bool isPrivate)
    {
        RSAParameters p = rsa.ExportParameters(isPrivate);
        var sb = new StringBuilder();
        sb.AppendLine($"Độ dài khoá : {rsa.KeySize} bit");
        sb.AppendLine();
        sb.AppendLine("n (Modulus) = p × q  [hex]:");
        sb.AppendLine(Wrap(Convert.ToHexString(p.Modulus)));
        sb.AppendLine();
        sb.AppendLine("n [thập phân]:");
        sb.AppendLine(Wrap(Big(p.Modulus).ToString()));
        sb.AppendLine();
        sb.AppendLine($"e (Public exponent) = {Big(p.Exponent)}  (hex {Convert.ToHexString(p.Exponent)}, {Big(p.Exponent).GetBitLength()} bit)");
        if (isPrivate)
        {
            sb.AppendLine();
            sb.AppendLine($"d (Private exponent, {Big(p.D).GetBitLength()} bit) [hex]:");
            sb.AppendLine(Wrap(Convert.ToHexString(p.D)));
            sb.AppendLine();
            sb.AppendLine("p (số nguyên tố 1) [hex]:");
            sb.AppendLine(Wrap(Convert.ToHexString(p.P)));
            sb.AppendLine();
            sb.AppendLine("q (số nguyên tố 2) [hex]:");
            sb.AppendLine(Wrap(Convert.ToHexString(p.Q)));
            sb.AppendLine();
            sb.AppendLine("dp = d mod (p-1) [hex]:");
            sb.AppendLine(Wrap(Convert.ToHexString(p.DP)));
            sb.AppendLine();
            sb.AppendLine("dq = d mod (q-1) [hex]:");
            sb.AppendLine(Wrap(Convert.ToHexString(p.DQ)));
            sb.AppendLine();
            sb.AppendLine("qinv = q^-1 mod p [hex]:");
            sb.AppendLine(Wrap(Convert.ToHexString(p.InverseQ)));
            sb.AppendLine();
            bool ok = Big(p.P) * Big(p.Q) == Big(p.Modulus);
            sb.AppendLine("Kiểm tra p × q == n : " + (ok ? "ĐÚNG" : "SAI"));
        }
        else
        {
            sb.AppendLine();
            sb.AppendLine("(File này chỉ chứa khoá công khai nên chỉ có n và e.)");
        }
        return sb.ToString();
    }

    public static string AsnDump(string pem)
    {
        byte[] der = PemToDer(pem);
        var sb = new StringBuilder();
        string header = pem.Replace("\r", "").Split('\n').FirstOrDefault(l => l.StartsWith("-----")) ?? "";
        sb.AppendLine("TẦNG 1 - VĂN BẢN PEM");
        sb.AppendLine("  Header : " + header);
        sb.AppendLine($"  Thân   : Base64 của dữ liệu nhị phân DER ({der.Length} byte)");
        sb.AppendLine("  Footer : -----END ...-----");
        sb.AppendLine();
        sb.AppendLine("TẦNG 2 - CẤU TRÚC DER / ASN.1  (mỗi phần tử = Tag | Length | Value)");
        sb.AppendLine("  @offset  các byte Tag+Length   loại phần tử   độ dài phần Value");
        sb.AppendLine();
        Dump(sb, der, 0, der.Length, 0);
        sb.AppendLine();
        sb.AppendLine("TẦNG 3 - Ý NGHĨA CÁC BYTE");
        sb.AppendLine("  Tag    : 30=SEQUENCE (nhóm phần tử con)   02=INTEGER (số nguyên lớn, big-endian)");
        sb.AppendLine("           03=BIT STRING   04=OCTET STRING   05=NULL   06=OBJECT IDENTIFIER");
        sb.AppendLine("  Length : < 0x80 là độ dài luôn;  81 XX = 1 byte độ dài;  82 XX XX = 2 byte độ dài");
        sb.AppendLine("  INTEGER có thêm byte 00 đứng đầu nếu bit cao nhất là 1 (để không bị hiểu là số âm)");
        sb.AppendLine("  OID 2A 86 48 86 F7 0D 01 01 01 = 1.2.840.113549.1.1.1 = rsaEncryption");
        return sb.ToString();
    }

    static void Dump(StringBuilder sb, byte[] d, int start, int end, int depth)
    {
        int pos = start;
        string pad = new string(' ', depth * 3);
        while (pos < end)
        {
            int tagPos = pos;
            byte tag = d[pos++];
            int len = d[pos++];
            if (len >= 0x80)
            {
                int n = len & 0x7F;
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | d[pos++];
            }
            int vStart = pos, vEnd = pos + len;
            byte[] hdr = d[tagPos..vStart];
            byte[] val = d[vStart..vEnd];
            string name = tag switch
            {
                0x30 => "SEQUENCE", 0x02 => "INTEGER", 0x03 => "BIT STRING",
                0x04 => "OCTET STRING", 0x05 => "NULL", 0x06 => "OBJECT IDENTIFIER", _ => "TAG " + tag.ToString("X2")
            };
            string line = $"  {pad}@{tagPos,4}  [{Spaced(hdr)}]  {name}  ({len} byte)";

            if (tag == 0x30)
            {
                sb.AppendLine(line);
                Dump(sb, d, vStart, vEnd, depth + 1);
            }
            else if (tag == 0x02)
            {
                var v = Big(val);
                sb.AppendLine($"{line}  = {(v.IsZero ? 0 : (int)v.GetBitLength())} bit, {Convert.ToHexString(val.Take(10).ToArray())}{(val.Length > 10 ? "..." : "")}");
            }
            else if (tag == 0x06)
            {
                sb.AppendLine($"{line}  = {DecodeOid(val)}{(DecodeOid(val) == "1.2.840.113549.1.1.1" ? " (rsaEncryption)" : "")}");
            }
            else if (tag == 0x05)
            {
                sb.AppendLine($"{line}  = rỗng (không có tham số)");
            }
            else if (tag == 0x03 && val.Length > 1 && val[1] == 0x30)
            {
                sb.AppendLine($"{line}  [byte đầu {val[0]:X2} = số bit thừa] chứa DER khoá RSA:");
                Dump(sb, d, vStart + 1, vEnd, depth + 1);
            }
            else if (tag == 0x04 && val.Length > 0 && val[0] == 0x30)
            {
                sb.AppendLine($"{line}  chứa DER khoá riêng RSA (PKCS#1):");
                Dump(sb, d, vStart, vEnd, depth + 1);
            }
            else
            {
                sb.AppendLine($"{line}  = {Convert.ToHexString(val.Take(12).ToArray())}{(val.Length > 12 ? "..." : "")}");
            }
            pos = vEnd;
        }
    }

    static string DecodeOid(byte[] v)
    {
        var sb = new StringBuilder();
        sb.Append(v[0] / 40).Append('.').Append(v[0] % 40);
        long cur = 0;
        for (int i = 1; i < v.Length; i++)
        {
            cur = (cur << 7) | (uint)(v[i] & 0x7F);
            if ((v[i] & 0x80) == 0) { sb.Append('.').Append(cur); cur = 0; }
        }
        return sb.ToString();
    }

    // ------------------------- Tốc độ RSA -------------------------
    // table 1: API .NET ; table 2: BigInteger.ModPow (không CRT)
    public static void RunSpeed(int iter, Action<int, object[]> report)
    {
        foreach (int bits in new[] { 1024, 2048, 3072, 4096 })
        {
            using var rsa = RSA.Create(bits);
            byte[] data = RandomNumberGenerator.GetBytes(32);
            byte[] c = rsa.Encrypt(data, Oaep);
            rsa.Decrypt(c, Oaep);
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iter; i++) c = rsa.Encrypt(data, Oaep);
            double tE = sw.Elapsed.TotalMilliseconds / iter;
            sw.Restart();
            for (int i = 0; i < iter; i++) rsa.Decrypt(c, Oaep);
            double tD = sw.Elapsed.TotalMilliseconds / iter;
            report(1, new object[] { bits, tE.ToString("F4"), tD.ToString("F4"), (tD / tE).ToString("F1") + " lần" });
        }
        foreach (int bits in new[] { 1024, 2048, 3072 })
        {
            using var rsa = RSA.Create(bits);
            RSAParameters p = rsa.ExportParameters(true);
            BigInteger n = Big(p.Modulus), e = Big(p.Exponent), d = Big(p.D);
            BigInteger m = Big(RandomNumberGenerator.GetBytes(bits / 8 - 1));
            BigInteger c = BigInteger.ModPow(m, e, n);
            int it = Math.Max(10, iter / 5);
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < it; i++) c = BigInteger.ModPow(m, e, n);
            double tE = sw.Elapsed.TotalMilliseconds / it;
            sw.Restart();
            BigInteger back = 0;
            for (int i = 0; i < it; i++) back = BigInteger.ModPow(c, d, n);
            double tD = sw.Elapsed.TotalMilliseconds / it;
            report(2, new object[] { bits, e.GetBitLength() + " bit", d.GetBitLength() + " bit",
                tE.ToString("F4"), tD.ToString("F4"), (tD / tE).ToString("F1") + " lần", back == m ? "Đúng" : "SAI" });
        }
    }

    // ------------------------- SHA-256 -------------------------
    public static byte[] Sha(string s) => SHA256.HashData(Encoding.UTF8.GetBytes(s ?? ""));

    public static int BitDiff(byte[] a, byte[] b)
    {
        int n = 0;
        for (int i = 0; i < Math.Min(a.Length, b.Length); i++) n += BitOperations.PopCount((uint)(a[i] ^ b[i]));
        return n;
    }

    public static bool[] DiffMask(byte[] a, byte[] b)
    {
        var m = new bool[256];
        for (int i = 0; i < 256; i++) m[i] = (((a[i / 8] ^ b[i / 8]) >> (7 - i % 8)) & 1) == 1;
        return m;
    }

    public static (double avg, int min, int max, int count) FlipStats(string s)
    {
        byte[] data = Encoding.UTF8.GetBytes(s ?? "");
        byte[] h0 = SHA256.HashData(data);
        long total = 0; int cnt = 0, min = 256, max = 0;
        for (int i = 0; i < data.Length; i++)
            for (int b = 0; b < 8; b++)
            {
                byte[] t = (byte[])data.Clone();
                t[i] ^= (byte)(1 << b);
                int dd = BitDiff(h0, SHA256.HashData(t));
                total += dd; cnt++; min = Math.Min(min, dd); max = Math.Max(max, dd);
            }
        return cnt == 0 ? (0, 0, 0, 0) : ((double)total / cnt, min, max, cnt);
    }

    // ------------------------- Chữ ký số -------------------------
    public static List<SigRow> SignDemo(RSA pri, RSA pub, byte[] data, int times)
    {
        var rows = new List<SigRow>();
        for (int i = 1; i <= times; i++)
        {
            byte[] s = pri.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rows.Add(new SigRow("PKCS#1 v1.5 (truyền thống)", i, Convert.ToBase64String(s),
                pub.VerifyData(data, s, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)));
        }
        for (int i = 1; i <= times; i++)
        {
            byte[] s = pri.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            rows.Add(new SigRow("Đề xuất 1: RSASSA-PSS (salt ngẫu nhiên)", i, Convert.ToBase64String(s),
                pub.VerifyData(data, s, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)));
        }
        for (int i = 1; i <= times; i++)
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(16);
            byte[] hash = SHA256.HashData(data.Concat(nonce).ToArray());
            byte[] sig = pri.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            byte[] pkg = nonce.Concat(sig).ToArray();                       // gói = nonce || chữ ký
            byte[] h2 = SHA256.HashData(data.Concat(pkg[..16]).ToArray());  // bên nhận tự băm lại
            bool ok = pub.VerifyHash(h2, pkg[16..], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rows.Add(new SigRow("Đề xuất 2: ký SHA256(dữ liệu || nonce)", i, Convert.ToBase64String(pkg), ok));
        }
        return rows;
    }
}
// ===== HẾT PHẦN LÕI =====

// =====================================================================
//  GIAO DIỆN (WinForms) - toàn bộ dựng bằng code, không cần file Designer
// =====================================================================
static class State
{
    public static readonly string Dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "ATBMTT");
    public static string PubPath = Path.Combine(Dir, "public.pem");
    public static string PriPath = Path.Combine(Dir, "private.pem");
    public static event Action PathsChanged;
    public static void SetPaths(string pub, string pri) { PubPath = pub; PriPath = pri; PathsChanged?.Invoke(); }
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


class BitPanel : Panel
{
    public bool[] Diff = new bool[256];
    public BitPanel() { DoubleBuffered = true; ResizeRedraw = true; BackColor = Color.White; }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        int cell = Math.Max(4, Math.Min(Width, Height) / 16);
        int ox = (Width - cell * 16) / 2, oy = (Height - cell * 16) / 2;
        using var same = new SolidBrush(Color.FromArgb(203, 213, 225));
        using var diff = new SolidBrush(Color.FromArgb(37, 99, 235));
        for (int i = 0; i < 256; i++)
        {
            var r = new Rectangle(ox + (i % 16) * cell + 1, oy + (i / 16) * cell + 1, cell - 2, cell - 2);
            e.Graphics.FillRectangle(Diff[i] ? diff : same, r);
        }
    }
}


// =====================================================================
//  CÁC TRANG CỦA BÀI 2
// =====================================================================
static class Pages
{
    // ---------------- BÀI 2 / Khoá RSA & PEM ----------------
    public static Control RsaKeys()
    {
        var page = new VStack();
        var gen = new Card("Sinh cặp khoá RSA và xuất ra file PEM");
        var cbo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = UI.H(140), Font = UI.Fnt(10) };
        cbo.Items.AddRange(new object[] { "1024", "2048", "3072", "4096" });
        cbo.SelectedIndex = 1;
        gen.Add(UI.Field("Độ dài khoá (bit)", cbo));
        var folder = UI.Txt(text: State.Dir);
        gen.Add(UI.Field("Thư mục lưu", folder, UI.Btn("Chọn...", (s, e) =>
        {
            string p = UI.PickFolder(folder.Text);
            if (p != null) folder.Text = p;
        }, false)));
        var bGen = UI.Btn("Sinh cặp khoá và lưu PEM", null);
        bGen.Click += async (s, e) =>
        {
            try
            {
                bGen.Enabled = false;
                UI.Status("Đang sinh khoá...");
                int bits = int.Parse((string)cbo.SelectedItem);
                string dir = folder.Text;
                Directory.CreateDirectory(dir);
                string pub = Path.Combine(dir, "public.pem"), pri = Path.Combine(dir, "private.pem");
                await Task.Run(() =>
                {
                    using var rsa = RSA.Create(bits);
                    File.WriteAllText(pub, rsa.ExportSubjectPublicKeyInfoPem());   // BEGIN PUBLIC KEY
                    File.WriteAllText(pri, rsa.ExportPkcs8PrivateKeyPem());        // BEGIN PRIVATE KEY
                });
                State.SetPaths(pub, pri);
                UI.Status($"Đã sinh cặp khoá {bits} bit: {pub} và {pri}");
                MessageBox.Show($"Đã tạo:\r\n{pub}\r\n{pri}\r\n\r\nKhông chia sẻ file private.pem cho ai.", "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex) { UI.Error(ex); }
            finally { bGen.Enabled = true; }
        };
        gen.Add(UI.Flow(bGen));
        page.Add(gen);

        var view = new Card("Xem và nhập file PEM: cấu trúc, ý nghĩa byte, tham số n, e, d...", true);
        var tPem = UI.Txt(multi: true, ro: true, mono: true);
        var tAsn = UI.Txt(multi: true, ro: true, mono: true);
        var tPar = UI.Txt(multi: true, ro: true, mono: true);
        var kind = UI.Lbl("Chưa mở file PEM nào.", muted: true);
        tAsn.WordWrap = false; tAsn.ScrollBars = ScrollBars.Both;
        view.Add(UI.Flow(UI.Btn("Mở file PEM...", (s, e) =>
        {
            try
            {
                string p = UI.OpenFile("File PEM|*.pem;*.key;*.txt|Tất cả tệp|*.*");
                if (p == null) return;
                string text = File.ReadAllText(p);
                using var rsa = Engine.LoadPem(text);
                bool pri = Engine.IsPrivatePem(text);
                kind.Text = Path.GetFileName(p) + "  →  " + Engine.KindOfPem(text) + $"  ({rsa.KeySize} bit)";
                tPem.Text = text.Replace("\r", "").Replace("\n", "\r\n");
                tAsn.Text = Engine.AsnDump(text).Replace("\r\n", "\n").Replace("\n", "\r\n");
                tPar.Text = Engine.PemParams(rsa, pri).Replace("\r\n", "\n").Replace("\n", "\r\n");
                UI.Status("Đã nhập " + (pri ? "private key" : "public key") + " từ " + p);
            }
            catch (Exception ex) { UI.Error(new Exception("Không đọc được file PEM: " + ex.Message)); }
        })));
        view.Add(kind);
        var tabs = new TabControl { Font = UI.Fnt(10), Margin = new Padding(0, UI.H(6), 0, 0) };
        foreach (var (title, box) in new[] { ("Cấu trúc ASN.1 / ý nghĩa byte", tAsn), ("Tham số khoá (n, e, d, ...)", tPar), ("Nội dung PEM", tPem) })
        {
            var tp = new TabPage(title) { BackColor = Color.White };
            box.Dock = DockStyle.Fill;
            tp.Controls.Add(box);
            tabs.TabPages.Add(tp);
        }
        view.Fill(tabs);
        page.Fill(view);
        return page;
    }

    // ---------------- BÀI 2 / Mã hoá giải mã RSA ----------------
    public static Control RsaCrypt()
    {
        var page = new VStack();
        var card = new Card("Mã hoá bằng public key, giải mã bằng private key (RSA-OAEP-SHA256)");
        card.Add(UI.Note("Giới hạn dữ liệu: 256 − 2×32 − 2 = 190 byte (khoá 2048 bit). Khoá AES-256 chỉ 32 byte nên mã hoá được. Bản mã luôn dài 256 byte và được lưu dạng Base64.", 44));
        var pub = UI.Txt(text: State.PubPath);
        var pri = UI.Txt(text: State.PriPath);
        State.PathsChanged += () => { pub.Text = State.PubPath; pri.Text = State.PriPath; };
        card.Add(UI.Field("File public key (.pem)", pub, UI.Btn("Chọn...", (s, e) => { string p = UI.OpenFile("PEM|*.pem|Tất cả|*.*"); if (p != null) pub.Text = p; }, false)));
        card.Add(UI.Field("File private key (.pem)", pri, UI.Btn("Chọn...", (s, e) => { string p = UI.OpenFile("PEM|*.pem|Tất cả|*.*"); if (p != null) pri.Text = p; }, false)));
        var rbAes = new RadioButton { Text = "Sinh khoá AES-256 ngẫu nhiên (32 byte)", Checked = true, AutoSize = true, Font = UI.Fnt(10), Margin = new Padding(0, UI.H(4), UI.H(24), 0) };
        var rbTxt = new RadioButton { Text = "Nhập văn bản (≤ 190 byte)", AutoSize = true, Font = UI.Fnt(10), Margin = new Padding(0, UI.H(4), 0, 0) };
        card.Add(UI.Field("Dữ liệu cần mã hoá", UI.Flow2(rbAes, rbTxt)));
        var txt = UI.Txt(text: "Xin chào, đây là dữ liệu bí mật");
        card.Add(UI.Field("Văn bản", txt));

        var outBox = UI.Txt(multi: true, ro: true, mono: true);
        var verdict = UI.Lbl("", bold: true, h: 30);
        verdict.Font = UI.Fnt(12, FontStyle.Bold);

        card.Add(UI.Flow(
            UI.Btn("Mã hoá và lưu file Base64...", (s, e) =>
            {
                try
                {
                    byte[] data = rbAes.Checked ? RandomNumberGenerator.GetBytes(32) : System.Text.Encoding.UTF8.GetBytes(txt.Text);
                    if (data.Length > 190) throw new InvalidOperationException($"Dữ liệu {data.Length} byte vượt quá 190 byte, RSA-2048 + OAEP-SHA256 không mã hoá được.");
                    string path = UI.SaveFile("cipher.b64", "Base64|*.b64|Tất cả|*.*");
                    if (path == null) return;
                    using var rsa = Engine.LoadPem(File.ReadAllText(pub.Text));
                    byte[] c = rsa.Encrypt(data, Engine.Oaep);
                    File.WriteAllText(path, Convert.ToBase64String(c));
                    File.WriteAllText(path + ".plain", Convert.ToBase64String(data));
                    outBox.Text = $"MÃ HOÁ THÀNH CÔNG\r\n  Dữ liệu gốc : {data.Length} byte\r\n  Base64 gốc  : {Convert.ToBase64String(data)}\r\n  Bản mã      : {c.Length} byte\r\n  Đã lưu      : {path}\r\n  Bản gốc để đối chiếu: {path}.plain\r\n\r\nBản mã (Base64):\r\n{Engine.Wrap(Convert.ToBase64String(c), 80).Replace("\n", "\r\n")}";
                    verdict.Text = "";
                    UI.Status("Đã mã hoá và lưu: " + path);
                }
                catch (Exception ex) { UI.Error(ex); }
            }),
            UI.Btn("Giải mã từ file Base64...", (s, e) =>
            {
                try
                {
                    string path = UI.OpenFile("Base64|*.b64|Tất cả|*.*");
                    if (path == null) return;
                    using var rsa = Engine.LoadPem(File.ReadAllText(pri.Text));
                    byte[] c = Convert.FromBase64String(File.ReadAllText(path).Trim());
                    byte[] plain = rsa.Decrypt(c, Engine.Oaep);
                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine("GIẢI MÃ THÀNH CÔNG");
                    sb.AppendLine($"  Dữ liệu sau giải mã: {plain.Length} byte");
                    sb.AppendLine($"  Base64 : {Convert.ToBase64String(plain)}");
                    string orig = path + ".plain";
                    if (File.Exists(orig))
                    {
                        byte[] src = Convert.FromBase64String(File.ReadAllText(orig).Trim());
                        bool same = src.AsSpan().SequenceEqual(plain);
                        verdict.Text = same ? "✔ Kết quả giải mã GIỐNG HỆT dữ liệu gốc" : "✘ Kết quả giải mã KHÁC dữ liệu gốc";
                        verdict.ForeColor = same ? UI.Ok : UI.Bad;
                    }
                    else { verdict.Text = "Không tìm thấy file .plain để đối chiếu"; verdict.ForeColor = UI.Muted; }
                    outBox.Text = sb.ToString().Replace("\r\n", "\n").Replace("\n", "\r\n");
                    UI.Status("Đã giải mã.");
                }
                catch (Exception ex) { UI.Error(new Exception("Giải mã thất bại (sai khoá hoặc dữ liệu hỏng): " + ex.Message)); }
            }, false)));
        page.Add(card);

        var res = new Card("Kết quả", true);
        res.Add(verdict);
        res.Fill(outBox);
        page.Fill(res);
        return page;
    }

    // ---------------- BÀI 2 / Tốc độ ----------------
    public static Control RsaSpeed()
    {
        var page = new VStack();
        var card = new Card("So sánh tốc độ: khoá công khai (e nhỏ) và khoá bí mật (d rất lớn)", true);
        card.Add(UI.Note("Phép dùng public key: m^e mod n với e = 65537 (17 bit). Phép dùng private key: c^d mod n với d cỡ hàng nghìn bit nên chậm hơn nhiều lần.", 44));
        var nud = new NumericUpDown { Minimum = 10, Maximum = 5000, Value = 200, Width = UI.H(120), Font = UI.Fnt(10) };
        card.Add(UI.Field("Số lần lặp mỗi phép đo", nud));
        var g1 = UI.Grid("Khoá (bit)", "Mã hoá / public (ms)", "Giải mã / private (ms)", "Giải mã chậm hơn");
        var g2 = UI.Grid("Khoá (bit)", "Bit của e", "Bit của d", "m^e mod n (ms)", "c^d mod n (ms)", "Chậm hơn", "Giải đúng");
        var bar = new ProgressBar { Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 30, Height = UI.H(18), Margin = Padding.Empty, Visible = false };
        var concl = UI.Note("", 64);
        concl.ForeColor = UI.Ink;
        var run = UI.Btn("Bắt đầu đo", null);
        run.Click += async (s, e) =>
        {
            try
            {
                run.Enabled = false; bar.Visible = true;
                g1.Rows.Clear(); g2.Rows.Clear(); concl.Text = "";
                UI.Status("Đang đo tốc độ RSA (có thể mất vài chục giây)...");
                int iter = (int)nud.Value;
                await Task.Run(() => Engine.RunSpeed(iter, (t, o) =>
                    run.BeginInvoke(new Action(() => (t == 1 ? g1 : g2).Rows.Add(o)))));
                concl.Text = "Kết luận: khoá công khai (e = 65537, 17 bit) nhanh hơn rất nhiều so với khoá bí mật (d cỡ độ dài n). " +
                             "Khoá càng dài, thời gian giải mã/ký tăng rất nhanh trong khi mã hoá tăng ít. Bảng B (không CRT) chênh lệch lớn hơn bảng A vì .NET dùng CRT (p, q, dp, dq, qinv) để tăng tốc giải mã.";
                UI.Status("Đo xong.");
            }
            catch (Exception ex) { UI.Error(ex); }
            finally { run.Enabled = true; bar.Visible = false; }
        };
        card.Add(UI.Flow(run));
        card.Add(bar);
        card.Add(UI.Lbl("A) API của .NET (RSA-OAEP-SHA256, dữ liệu 32 byte)", bold: true));
        card.Fill(g1);
        card.Add(UI.Lbl("B) RSA thuần bằng BigInteger.ModPow (không dùng CRT)", bold: true));
        card.Fill(g2);
        card.Add(concl);
        page.Fill(card);
        return page;
    }

    // ---------------- BÀI 2 / SHA-256 ----------------
    public static Control Sha()
    {
        var page = new VStack();
        var card = new Card("Băm SHA-256 và hiệu ứng tuyết lở (avalanche)", true);
        card.Add(UI.Note("Gõ vào 2 ô bên dưới: chỉ cần đổi 1 ký tự (hoặc 1 bit), chuỗi băm thay đổi khoảng một nửa số bit (≈128/256).", 40));
        var t1 = UI.Txt(multi: true, text: "Hello World");
        var t2 = UI.Txt(multi: true, text: "Hello World!");
        var h1 = UI.Txt(ro: true, mono: true);
        var h2 = UI.Txt(ro: true, mono: true);
        var info = UI.Lbl("", bold: true, h: 28);
        var stat = UI.Lbl("", muted: true);
        var bits = new BitPanel { Margin = Padding.Empty };
        var t1w = new Panel { Height = UI.H(54) }; t1.Dock = DockStyle.Fill; t1w.Controls.Add(t1);
        var t2w = new Panel { Height = UI.H(54) }; t2.Dock = DockStyle.Fill; t2w.Controls.Add(t2);
        card.Add(UI.Field("Chuỗi 1", t1w, null, 62));
        card.Add(UI.Field("Chuỗi 2", t2w, null, 62));
        card.Add(UI.Field("SHA-256 (chuỗi 1)", h1));
        card.Add(UI.Field("SHA-256 (chuỗi 2)", h2));

        void Update()
        {
            byte[] a = Engine.Sha(t1.Text), b = Engine.Sha(t2.Text);
            h1.Text = Convert.ToHexString(a);
            h2.Text = Convert.ToHexString(b);
            int d = Engine.BitDiff(a, b);
            bits.Diff = Engine.DiffMask(a, b);
            bits.Invalidate();
            info.Text = $"Kết quả băm khác nhau {d}/256 bit = {d / 256.0 * 100:F1}%   (kỳ vọng ≈ 50%, tức ≈ 128 bit)";
            info.ForeColor = UI.Accent;
        }
        t1.TextChanged += (s, e) => Update();
        t2.TextChanged += (s, e) => Update();

        card.Add(UI.Flow(
            UI.Btn("Chuỗi 2 = chuỗi 1 lật đúng 1 bit", (s, e) =>
            {
                if (t1.Text.Length == 0) return;
                char[] cs = t1.Text.ToCharArray();
                cs[0] = (char)(cs[0] ^ 1);
                t2.Text = new string(cs);
            }),
            UI.Btn("Thống kê lật từng bit của chuỗi 1", (s, e) =>
            {
                var r = Engine.FlipStats(t1.Text);
                stat.Text = r.count == 0 ? "Chuỗi 1 đang rỗng." :
                    $"Lật lần lượt {r.count} bit của chuỗi 1: trung bình {r.avg:F1} bit khác, ít nhất {r.min}, nhiều nhất {r.max} (trên 256 bit).";
            }, false),
            UI.Btn("Băm một file...", (s, e) =>
            {
                try
                {
                    string p = UI.OpenFile();
                    if (p == null) return;
                    using var fs = File.OpenRead(p);
                    stat.Text = "SHA-256 của file: " + Convert.ToHexString(SHA256.HashData(fs));
                }
                catch (Exception ex) { UI.Error(ex); }
            }, false)));
        card.Add(info);
        card.Add(stat);
        card.Add(UI.Lbl("Bản đồ 256 bit của chuỗi băm: ô xanh = bit thay đổi, ô xám = bit giữ nguyên", muted: true));
        card.Fill(bits);
        page.Fill(card);
        Update();
        return page;
    }

    // ---------------- BÀI 2 / Chữ ký số ----------------
    public static Control Sign()
    {
        var page = new VStack();
        var card = new Card("Chữ ký số RSA: cùng dữ liệu, cùng người ký nhưng mỗi lần ký một khác");
        card.Add(UI.Note("Chữ ký truyền thống PKCS#1 v1.5 là tất định nên ký lại ra y hệt. Đề xuất 1: RSASSA-PSS thêm salt ngẫu nhiên (chuẩn RFC 8017, salt nằm trong chữ ký, bên nhận vẫn verify bình thường). Đề xuất 2: ký SHA256(dữ liệu || nonce) rồi gửi kèm nonce.", 58));
        var pub = UI.Txt(text: State.PubPath);
        var pri = UI.Txt(text: State.PriPath);
        State.PathsChanged += () => { pub.Text = State.PubPath; pri.Text = State.PriPath; };
        var data = UI.Txt(text: "Hop dong so 01");
        card.Add(UI.Field("File private key", pri, UI.Btn("Chọn...", (s, e) => { string p = UI.OpenFile("PEM|*.pem|Tất cả|*.*"); if (p != null) pri.Text = p; }, false)));
        card.Add(UI.Field("File public key", pub, UI.Btn("Chọn...", (s, e) => { string p = UI.OpenFile("PEM|*.pem|Tất cả|*.*"); if (p != null) pub.Text = p; }, false)));
        card.Add(UI.Field("Dữ liệu cần ký", data));

        var grid = UI.Grid("Phương pháp", "Lần ký", "Chữ ký (Base64, rút gọn)", "Verify");
        grid.Columns[0].FillWeight = 130; grid.Columns[1].FillWeight = 30; grid.Columns[2].FillWeight = 200; grid.Columns[3].FillWeight = 40;
        var concl = UI.Txt(multi: true, ro: true);

        card.Add(UI.Flow(
            UI.Btn("Ký 3 lần mỗi phương pháp", (s, e) =>
            {
                try
                {
                    using var rp = Engine.LoadPem(File.ReadAllText(pri.Text));
                    using var rb = Engine.LoadPem(File.ReadAllText(pub.Text));
                    var rows = Engine.SignDemo(rp, rb, System.Text.Encoding.UTF8.GetBytes(data.Text), 3);
                    grid.Rows.Clear();
                    foreach (var r in rows)
                    {
                        int i = grid.Rows.Add(r.Method, r.Idx, r.Sig.Substring(0, Math.Min(56, r.Sig.Length)) + "...", r.Ok ? "True" : "False");
                        grid.Rows[i].Cells[3].Style.ForeColor = r.Ok ? UI.Ok : UI.Bad;
                    }
                    var sb = new System.Text.StringBuilder();
                    foreach (var g in rows.GroupBy(x => x.Method))
                    {
                        int distinct = g.Select(x => x.Sig).Distinct().Count();
                        bool allOk = g.All(x => x.Ok);
                        sb.AppendLine($"• {g.Key}: {distinct}/3 chữ ký khác nhau, verify {(allOk ? "đều ĐÚNG" : "CÓ LỖI")}" +
                                      (distinct == 1 ? "  → tất định, KHÔNG đạt mong muốn." : "  → ĐẠT mong muốn."));
                        foreach (var x in g) grid.Rows[rows.IndexOf(x)].DefaultCellStyle.BackColor = distinct == 1 ? Color.FromArgb(254, 242, 242) : Color.FromArgb(240, 253, 244);
                    }
                    concl.Text = sb.ToString().Replace("\r\n", "\n").Replace("\n", "\r\n");
                    UI.Status("Đã ký và kiểm tra chữ ký.");
                }
                catch (Exception ex) { UI.Error(ex); }
            }),
            UI.Btn("Sửa dữ liệu rồi verify chữ ký cũ", (s, e) =>
            {
                try
                {
                    using var rp = Engine.LoadPem(File.ReadAllText(pri.Text));
                    using var rb = Engine.LoadPem(File.ReadAllText(pub.Text));
                    byte[] d = System.Text.Encoding.UTF8.GetBytes(data.Text);
                    byte[] sig = rp.SignData(d, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                    bool ok1 = rb.VerifyData(d, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                    bool ok2 = rb.VerifyData(System.Text.Encoding.UTF8.GetBytes(data.Text + "!"), sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                    concl.Text = $"Dữ liệu gốc + chữ ký PSS → verify = {ok1}\r\nSửa dữ liệu (thêm 1 ký tự) + chữ ký cũ → verify = {ok2}  (phải là False: chữ ký bảo vệ tính toàn vẹn)";
                }
                catch (Exception ex) { UI.Error(ex); }
            }, false)));
        page.Add(card);

        var res = new Card("Kết quả", true);
        res.Fill(grid);
        res.Add(UI.Lbl("Kết luận", bold: true));
        var wrap = new Panel { Height = UI.H(96) };
        concl.Dock = DockStyle.Fill;
        wrap.Controls.Add(concl);
        res.Add(wrap);
        page.Fill(res);
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
        Text = "Bài 2 - RSA, SHA-256, Chữ ký số";
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
            Text = "BÀI 2: RSA\r\nSHA-256 · CHỮ KÝ SỐ", AutoSize = false, Width = UI.H(260), Height = UI.H(96),
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

        Group("RSA · SHA-256 · CHỮ KÝ SỐ");
        Item("Khoá RSA và file PEM", "Sinh khoá, xuất PEM, xem cấu trúc, lấy n, e, d", Pages.RsaKeys);
        Item("Mã hoá / giải mã RSA", "Mã hoá ≤ 190 byte, lưu Base64, giải mã, đối chiếu", Pages.RsaCrypt);
        Item("Đánh giá tốc độ RSA", "Public key (e nhỏ) so với private key (d lớn)", Pages.RsaSpeed);
        Item("Băm SHA-256", "Hiệu ứng tuyết lở khi đầu vào đổi rất ít", Pages.Sha);
        Item("Chữ ký số", "Mỗi lần ký ra một chữ ký khác nhau (PSS, nonce)", Pages.Sign);
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

