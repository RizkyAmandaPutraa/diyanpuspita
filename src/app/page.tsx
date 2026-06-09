"use client";

import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, Search, Activity, AlertTriangle, CheckCircle, Zap, Database, Code, Key, ShieldAlert, Network, Cookie, FileText, Lock, Server, Settings, Users, FileDown, X, BookOpen } from "lucide-react";
import { createClient } from "@supabase/supabase-js";

// Initialize Supabase client
const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL || "",
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || ""
);

const SCAN_MODULES = [
  { id: 'sql', name: 'SQL Injection Scanner', icon: Database },
  { id: 'xss', name: 'XSS Scanner', icon: Code },
  { id: 'jwt', name: 'JWT Security Test', icon: Key },
  { id: 'csrf', name: 'CSRF Audit', icon: ShieldAlert },
  { id: 'api', name: 'API Security Scanner', icon: Network },
  { id: 'cookie', name: 'Session Cookie Audit', icon: Cookie },
  { id: 'header', name: 'Security Header Check', icon: FileText },
  { id: 'https', name: 'HTTPS Validation', icon: Lock },
  { id: 'server', name: 'Server Information Audit', icon: Server },
  { id: 'crawl', name: 'Internal Page Crawling', icon: Search },
  { id: 'config', name: 'Security Configuration Detection', icon: Settings },
  { id: 'admin', name: 'Admin Panel Discovery', icon: Users }
];

const getSuccessExplanation = (id: string) => {
  switch (id) {
    case 'sql': return "Tidak ditemukan pola input yang mengizinkan injeksi kode SQL. Parameter pada URL dan formulir tampaknya telah di-filter atau menggunakan parameterized queries dengan baik.";
    case 'xss': return "Tidak ada potensi eksekusi script lintas situs (XSS). Seluruh input dari pengguna telah dibersihkan (sanitized) dan di-escape sebelum ditampilkan kembali di halaman web.";
    case 'jwt': return "Implementasi JWT aman. Tidak ada kerentanan terhadap serangan penggantian algoritma 'none' dan mekanisme signature tervalidasi dengan baik.";
    case 'csrf': return "Token Anti-CSRF yang unik telah ditemukan di formulir web. Situs ini terlindungi dari aksi manipulasi paksa lintas situs (Cross-Site Request Forgery).";
    case 'api': return "Endpoint API terlindungi dengan baik. Tidak mengekspos data sensitif secara publik dan sistem kontrol akses beroperasi dengan konfigurasi CORS yang aman.";
    case 'cookie': return "Cookie otentikasi / sesi telah diatur dengan atribut 'HttpOnly' dan 'Secure', mengamankannya dari pencurian via script (XSS) dan pemantauan jaringan (Sniffing).";
    case 'header': return "Header keamanan HTTP kritis (seperti Content-Security-Policy dan X-Frame-Options) terkonfigurasi dengan tepat untuk menangkal serangan Clickjacking dan Code Injection.";
    case 'https': return "Website beroperasi penuh di atas SSL/TLS (HTTPS), memastikan integritas dan enkripsi data (End-to-End Encryption) antara perangkat pengguna dan server.";
    case 'server': return "Sistem tidak membocorkan versi web server (seperti versi spesifik Nginx/Apache) atau informasi teknologi backend yang dapat mempermudah pengintaian (Profiling) oleh peretas.";
    case 'crawl': return "Proses crawler otomatis tidak menemukan direktori sensitif, file konfigurasi tersembunyi (.env), atau dokumen cadangan (.bak) yang terekspos ke internet.";
    case 'config': return "Deteksi konfigurasi keamanan mendapati infrastruktur server beroperasi sesuai dengan praktik standar keamanan terbaik (Security Best Practices).";
    case 'admin': return "Panel administrasi tidak ditemukan pada path yang umum atau mudah ditebak (misalnya /admin, /administrator, /login). Hal ini menekan risiko serangan brute-force.";
    default: return "Sistem memvalidasi modul ini dengan sukses. Tidak ada anomali atau celah keamanan yang terdeteksi.";
  }
};

export default function Home() {
  const [targetUrl, setTargetUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [logs, setLogs] = useState<{msg: string, isError?: boolean, isWarning?: boolean}[]>([]);
  const [scanStats, setScanStats] = useState({ score: 0, vulnerabilities: 0, pagesScanned: 0 });
  const [moduleStatus, setModuleStatus] = useState<Record<string, 'pending' | 'scanning' | 'passed' | 'failed'>>({});
  const [findings, setFindings] = useState<{id: number, moduleId: string, type: string, severity: string}[]>([]);
  const [selectedModule, setSelectedModule] = useState<string | null>(null);
  const [scannedUrl, setScannedUrl] = useState("");
  
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Listen to Supabase Realtime broadcast for scan updates
    const channel = supabase.channel('scan_events')
      .on('broadcast', { event: 'scan_update' }, (payload) => {
        setScanProgress(payload.payload.progress);
        setLogs((prev) => [...prev, { msg: `> ${payload.payload.msg}` }]);
        if (payload.payload.moduleUpdate) {
           setModuleStatus(prev => ({
             ...prev, 
             [payload.payload.moduleUpdate.id]: payload.payload.moduleUpdate.status
           }));
        }
      })
      .on('broadcast', { event: 'scan_complete' }, (payload) => {
        setIsScanning(false);
        setScanProgress(100);
        setLogs((prev) => [...prev, { msg: `> ${payload.payload.message}` }]);
        setScanStats({
          score: payload.payload.score,
          vulnerabilities: payload.payload.findings?.length || 0,
          pagesScanned: payload.payload.pagesScanned || 0
        });
        setFindings(payload.payload.findings || []);
        if (payload.payload.moduleStatuses) {
           setModuleStatus(prev => ({
             ...prev,
             ...payload.payload.moduleStatuses
           }));
        }
      })
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, []);

  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  const startScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl) return;
    
    setScannedUrl(targetUrl);
    setIsScanning(true);
    setScanProgress(0);
    setLogs([{ msg: `> Initiating scan for ${targetUrl}` }]);
    setScanStats({ score: 0, vulnerabilities: 0, pagesScanned: 0 });
    setFindings([]);
    setSelectedModule(null);
    
    // Reset module statuses to pending
    const initialStatuses: Record<string, 'pending'> = {};
    SCAN_MODULES.forEach(m => initialStatuses[m.id] = 'pending');
    setModuleStatus(initialStatuses);
    
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl })
      });
      if (!response.ok) {
        setLogs((prev) => [...prev, { msg: '> Error initiating scan', isError: true }]);
        setIsScanning(false);
      }
    } catch (error) {
      setLogs((prev) => [...prev, { msg: '> Network error starting scan', isError: true }]);
      setIsScanning(false);
    }
  };

  const exportToPDF = async () => {
    if (scanStats.score === 0) return;
    
    const { jsPDF } = await import('jspdf');
    const doc = new jsPDF();
    const now = new Date().toLocaleString('id-ID');
    const pageWidth = doc.internal.pageSize.getWidth();

    // Header
    doc.setFillColor(6, 182, 212);
    doc.rect(0, 0, pageWidth, 28, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('LAPORAN SECURITY AUDIT', pageWidth / 2, 12, { align: 'center' });
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text('Testing System - Realtime Security Audit Dashboard', pageWidth / 2, 20, { align: 'center' });

    // Meta
    doc.setTextColor(50, 50, 50);
    doc.setFontSize(10);
    let y = 36;
    doc.setFont('helvetica', 'bold');
    doc.text('Target URL:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(scannedUrl, 45, y);
    y += 7;
    doc.setFont('helvetica', 'bold');
    doc.text('Tanggal Scan:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(now, 48, y);
    y += 7;
    doc.setFont('helvetica', 'bold');
    doc.text('Halaman Dipindai:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(String(scanStats.pagesScanned), 57, y);
    y += 12;

    // Score box
    const scoreColor: [number, number, number] = scanStats.score >= 80 ? [34, 197, 94] : scanStats.score >= 50 ? [234, 179, 8] : [239, 68, 68];
    doc.setFillColor(...scoreColor);
    doc.roundedRect(14, y, pageWidth - 28, 20, 4, 4, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(13);
    doc.setFont('helvetica', 'bold');
    doc.text(`Skor Keamanan: ${scanStats.score} / 100   |   Total Kerentanan: ${scanStats.vulnerabilities}`, pageWidth / 2, y + 13, { align: 'center' });
    y += 28;

    // Module results
    doc.setTextColor(30, 30, 30);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('Hasil Pemindaian Per Modul', 14, y);
    y += 2;
    doc.setDrawColor(200, 200, 200);
    doc.line(14, y + 2, pageWidth - 14, y + 2);
    y += 8;

    SCAN_MODULES.forEach((mod) => {
      const status = moduleStatus[mod.id] || 'pending';
      const modFindings = findings.filter(f => f.moduleId === mod.id);
      if (status === 'pending') return;

      if (y > 265) {
        doc.addPage();
        y = 20;
      }

      const dotColor: [number, number, number] = status === 'passed' ? [34, 197, 94] : status === 'failed' ? [239, 68, 68] : [156, 163, 175];
      doc.setFillColor(...dotColor);
      doc.circle(18, y - 1, 2.5, 'F');

      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(30, 30, 30);
      doc.text(mod.name, 24, y);

      const label = status === 'passed' ? 'AMAN' : status === 'failed' ? 'RENTAN' : 'N/A';
      doc.setTextColor(...dotColor);
      doc.setFont('helvetica', 'bold');
      doc.text(label, pageWidth - 14, y, { align: 'right' });
      y += 6;

      if (modFindings.length > 0) {
        modFindings.forEach(f => {
          if (y > 265) { doc.addPage(); y = 20; }
          doc.setFontSize(9);
          doc.setFont('helvetica', 'normal');
          doc.setTextColor(180, 50, 50);
          doc.text(`  \u2022 ${f.type} [${f.severity.toUpperCase()}]`, 24, y);
          y += 5;
        });
      } else if (status === 'passed') {
        doc.setFontSize(9);
        doc.setFont('helvetica', 'italic');
        doc.setTextColor(100, 100, 100);
        const explanation = getSuccessExplanation(mod.id);
        const lines = doc.splitTextToSize(explanation, pageWidth - 42);
        if (y + lines.length * 4.5 > 265) { doc.addPage(); y = 20; }
        doc.text(lines, 24, y);
        y += lines.length * 4.5;
      }
      y += 5;
    });

    // Footer
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.setFont('helvetica', 'italic');
    const totalPages = (doc.internal as any).getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      doc.text(`Halaman ${i} dari ${totalPages}  |  Laporan dibuat otomatis oleh Testing System Security Audit`, pageWidth / 2, 290, { align: 'center' });
    }

    doc.save(`laporan-security-audit-${new Date().getTime()}.pdf`);
  };

  const exportTechPDF = async () => {
    const { jsPDF } = await import('jspdf');
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const now = new Date().toLocaleString('id-ID');
    const margin = 14;
    let y = 0;

    // Header block
    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, pageWidth, 32, 'F');
    doc.setFillColor(6, 182, 212);
    doc.rect(0, 29, pageWidth, 3, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text('DOKUMENTASI TEKNOLOGI', pageWidth / 2, 13, { align: 'center' });
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(148, 163, 184);
    doc.text('Testing System - Security Audit Dashboard', pageWidth / 2, 22, { align: 'center' });
    y = 42;

    // Metadata row
    doc.setFontSize(8.5);
    doc.setTextColor(100, 116, 139);
    doc.text(`Dicetak: ${now}`, margin, y);
    doc.text('Versi: 1.0.0', pageWidth - margin, y, { align: 'right' });
    y += 10;

    // Section helper
    const sectionTitle = (title: string) => {
      doc.setFillColor(241, 245, 249);
      doc.rect(margin, y, pageWidth - margin * 2, 8, 'F');
      doc.setTextColor(15, 23, 42);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text(title, margin + 3, y + 5.5);
      y += 12;
    };

    const row = (label: string, value: string, note: string = '') => {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(30, 41, 59);
      doc.text(label, margin + 3, y);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text(value, margin + 52, y);
      if (note) {
        doc.setFont('helvetica', 'italic');
        doc.setFontSize(8);
        doc.setTextColor(148, 163, 184);
        doc.text(note, margin + 3, y + 5);
        y += 5;
      }
      y += 7;
    };

    // === 1. PENGANTAR ===
    sectionTitle('1. Gambaran Umum Proyek');
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    const intro = 'Testing System adalah aplikasi web berbasis Next.js yang dirancang untuk melakukan pemindaian keamanan (security audit) terhadap website target secara realtime. Hasil pemindaian ditampilkan secara langsung melalui koneksi WebSocket menggunakan Supabase Realtime, sehingga pengguna dapat memantau progres dan temuan tanpa perlu me-refresh halaman.';
    const introLines = doc.splitTextToSize(intro, pageWidth - margin * 2);
    doc.text(introLines, margin + 3, y);
    y += introLines.length * 5 + 6;

    // === 2. FRAMEWORK ===
    sectionTitle('2. Framework & Runtime Utama');
    row('Next.js 16.2.7', 'Full-stack React Framework', 'Digunakan sebagai fondasi utama: mengelola routing, rendering (App Router), dan API Route untuk backend scanning engine.');
    row('React 19.2.4', 'UI Library', 'Dipakai untuk membangun antarmuka pengguna berbasis komponen yang reaktif dan efisien.');
    row('TypeScript 5', 'Typed JavaScript', 'Memberikan pengecekan tipe statis sehingga menekan bug logika sejak tahap pengembangan.');
    row('Node.js', 'Server Runtime', 'Menjalankan API Route Next.js di sisi server, termasuk proses fetching dan parsing HTML target.');

    // === 3. STYLING ===
    sectionTitle('3. Styling & Komponen UI');
    row('Tailwind CSS v4', 'Utility-first CSS', 'Digunakan untuk seluruh desain tampilan dengan pendekatan utility class yang konsisten dan cepat.');
    row('Framer Motion', 'Animasi UI', 'Menambahkan animasi halus pada komponen: progress bar, kemunculan modal, dan transisi antar status card.');
    row('Lucide React', 'Icon Library', 'Menyediakan ikon-ikon yang digunakan pada seluruh antarmuka (navbar, card modul, tombol, dsb.).');

    // === 4. REALTIME ===
    sectionTitle('4. Komunikasi Realtime');
    row('Supabase', 'Backend-as-a-Service', 'Platform backend yang menyediakan infrastruktur database dan komunikasi realtime berbasis PostgreSQL.');
    row('Supabase Realtime', 'WebSocket Broadcast', 'Digunakan untuk mengirimkan update status scanning dari server ke browser secara instan tanpa polling, memanfaatkan protokol WebSocket.');

    // === 5. SCANNING ENGINE ===
    sectionTitle('5. Modul Scanning (Backend)');
    row('Axios', 'HTTP Client', 'Melakukan request HTTP ke URL target dengan konfigurasi timeout, mengambil response header dan body HTML.');
    row('Cheerio', 'HTML Parser', 'Mengurai dan menganalisis struktur DOM dari HTML yang diambil, seperti mendeteksi formulir, input, dan atribut keamanan.');

    // === 6. LAPORAN ===
    sectionTitle('6. Ekspor Laporan');
    row('jsPDF', 'PDF Generator', 'Digunakan untuk membuat dan mengunduh file laporan PDF langsung dari browser, tanpa proses server-side.');

    // === 7. ALUR ARSITEKTUR ===
    sectionTitle('7. Alur Arsitektur Sistem');
    const steps = [
      '1. Pengguna memasukkan URL target dan menekan Mulai Pemindaian.',
      '2. Frontend mengirim POST request ke endpoint API: /api/scan.',
      '3. API Route di server mengakses URL target menggunakan Axios, mengambil header dan HTML.',
      '4. Cheerio mem-parsing HTML untuk mendeteksi formulir, token, dan struktur keamanan.',
      '5. Setiap modul yang selesai diperiksa mengirim broadcast ke channel Supabase Realtime.',
      '6. Frontend menerima event secara realtime dan memperbarui UI (progress, status card, log terminal).',
      '7. Saat seluruh modul selesai, laporan dapat diekspor ke format PDF.',
    ];
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    steps.forEach(step => {
      if (y > 265) { doc.addPage(); y = 20; }
      const lines = doc.splitTextToSize(step, pageWidth - margin * 2 - 6);
      doc.text(lines, margin + 3, y);
      y += lines.length * 5 + 2;
    });
    y += 4;

    // === 8. MODUL AUDIT ===
    sectionTitle('8. Daftar Modul Audit Keamanan');
    const modules = [
      ['SQL Injection Scanner', 'Mendeteksi potensi celah injeksi kode SQL pada parameter URL dan formulir.'],
      ['XSS Scanner', 'Memeriksa kemungkinan eksekusi skrip lintas situs melalui input yang tidak di-sanitasi.'],
      ['JWT Security Test', 'Memvalidasi mekanisme token JWT: algoritma, signature, dan ekspirasi.'],
      ['CSRF Audit', 'Mencari keberadaan token anti-CSRF pada setiap formulir yang ditemukan.'],
      ['API Security Scanner', 'Memeriksa konfigurasi CORS dan keterbukaan data sensitif pada endpoint API.'],
      ['Session Cookie Audit', 'Memverifikasi atribut HttpOnly dan Secure pada cookie sesi/autentikasi.'],
      ['Security Header Check', 'Menganalisis respons header HTTP: CSP, X-Frame-Options, HSTS, dsb.'],
      ['HTTPS Validation', 'Memastikan website beroperasi penuh di atas SSL/TLS.'],
      ['Server Information Audit', 'Mendeteksi apakah server membocorkan versi atau teknologi yang digunakan.'],
      ['Internal Page Crawling', 'Menelusuri halaman dan direktori secara otomatis untuk menemukan aset tersembunyi.'],
      ['Security Configuration Detection', 'Memeriksa kesesuaian konfigurasi server dengan standar keamanan terkini.'],
      ['Admin Panel Discovery', 'Mencoba mengakses path umum panel admin untuk menguji keterpaparan akses.'],
    ];
    modules.forEach(([name, desc]) => {
      if (y > 265) { doc.addPage(); y = 20; }
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      doc.text(`• ${name}`, margin + 3, y);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(100, 116, 139);
      const dLines = doc.splitTextToSize(desc, pageWidth - margin * 2 - 10);
      doc.text(dLines, margin + 8, y + 5);
      y += dLines.length * 4.5 + 8;
    });

    // Footer setiap halaman
    const totalPages = (doc.internal as any).getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      doc.setFillColor(241, 245, 249);
      doc.rect(0, 286, pageWidth, 11, 'F');
      doc.setFontSize(7.5);
      doc.setTextColor(148, 163, 184);
      doc.setFont('helvetica', 'normal');
      doc.text(`Testing System | Dokumentasi Teknologi`, margin, 292);
      doc.text(`Halaman ${i} dari ${totalPages}`, pageWidth - margin, 292, { align: 'right' });
    }

    doc.save('dokumentasi-teknologi-testing-system.pdf');
  };

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-50 font-sans selection:bg-cyan-500/30">
      {/* Background Grid */}
      <div className="fixed inset-0 z-0 bg-[linear-gradient(to_right,#4f4f4f2e_1px,transparent_1px),linear-gradient(to_bottom,#4f4f4f2e_1px,transparent_1px)] bg-[size:14px_24px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)]"></div>

      {/* Navbar */}
      <nav className="relative z-10 border-b border-neutral-800 bg-neutral-950/50 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-cyan-400" />
            <span className="text-xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
              TESTING SYSTEM
            </span>
          </div>
          <div className="flex items-center gap-3">
            <button 
              onClick={exportToPDF}
              disabled={scanStats.score === 0}
              className="flex items-center gap-2 px-4 py-2 text-sm font-semibold text-neutral-950 bg-cyan-400 rounded-md hover:bg-cyan-300 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <FileDown className="w-4 h-4" />
              Export PDF
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="text-center mb-12">
          <h1 className="text-4xl md:text-6xl font-extrabold mb-6">
            Dashboard <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">Security Audit</span> Realtime
          </h1>
          <p className="text-lg text-neutral-400 max-w-2xl mx-auto">
            Pindai aplikasi web Anda dari kerentanan, kesalahan konfigurasi, dan risiko keamanan secara instan. Dapatkan laporan detail dan wawasan yang dapat ditindaklanjuti.
          </p>
        </div>

        {/* Scanner Input */}
        <div className="max-w-3xl mx-auto mb-16">
          <form onSubmit={startScan} className="relative flex items-center">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <Search className="h-5 w-5 text-neutral-500" />
            </div>
            <input
              type="url"
              placeholder="https://example.com"
              required
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              disabled={isScanning}
              className="w-full pl-12 pr-40 py-4 bg-neutral-900 border border-neutral-800 rounded-xl text-lg focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={isScanning}
              className="absolute right-2 top-2 bottom-2 px-6 bg-cyan-500 hover:bg-cyan-400 text-neutral-950 font-bold rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isScanning ? (
                <>
                  <Activity className="w-5 h-5 animate-pulse" />
                  Memindai
                </>
              ) : (
                <>
                  <Zap className="w-5 h-5" />
                  Mulai Pemindaian
                </>
              )}
            </button>
          </form>
        </div>

        {/* Realtime Progress & Live Logs */}
        <AnimatePresence>
          {(isScanning || scanProgress === 100) && (
            <motion.div 
              initial={{ opacity: 0, y: 20, height: 0 }}
              animate={{ opacity: 1, y: 0, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="max-w-3xl mx-auto mb-12 p-6 bg-neutral-900 border border-neutral-800 rounded-xl overflow-hidden"
            >
              <div className="flex justify-between items-center mb-4">
                <span className="text-cyan-400 font-mono text-sm">
                  {isScanning ? "Pemindaian sedang berlangsung..." : "Pemindaian Selesai"}
                </span>
                <span className="font-mono">{scanProgress}%</span>
              </div>
              
              <div className="w-full bg-neutral-800 rounded-full h-2 mb-6 overflow-hidden">
                <motion.div 
                  className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full"
                  initial={{ width: 0 }}
                  animate={{ width: `${scanProgress}%` }}
                  transition={{ ease: "linear" }}
                />
              </div>
              
              {/* Live Terminal Log */}
              <div className="bg-neutral-950 border border-neutral-800 rounded-lg p-4 h-48 overflow-y-auto font-mono text-sm shadow-inner relative">
                <div className="flex flex-col gap-1">
                  {logs.map((log, idx) => (
                    <motion.div 
                      key={idx}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      className={`
                        ${log.isError ? 'text-red-400' : ''} 
                        ${log.isWarning ? 'text-yellow-400' : ''} 
                        ${!log.isError && !log.isWarning ? 'text-green-400' : ''}
                      `}
                    >
                      {log.msg}
                    </motion.div>
                  ))}
                  {isScanning && (
                    <div className="text-cyan-400 animate-pulse mt-2">_</div>
                  )}
                  <div ref={logEndRef} />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Audit Modules Grid */}
        <div className="mb-12">
          <h2 className="text-2xl font-bold mb-6 flex items-center gap-3">
            <Shield className="text-cyan-400" /> Modul Audit Sistem
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
            {SCAN_MODULES.map((mod) => {
              const status = moduleStatus[mod.id] || 'pending';
              
              return (
                <div 
                  key={mod.id} 
                  onClick={() => setSelectedModule(mod.id)}
                  className={`cursor-pointer p-4 bg-neutral-900 border rounded-xl flex flex-col gap-3 transition-all duration-300 ${status === 'passed' ? 'border-green-500/50 shadow-[0_0_15px_rgba(34,197,94,0.1)] hover:shadow-[0_0_20px_rgba(34,197,94,0.2)]' : status === 'failed' ? 'border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.1)] hover:shadow-[0_0_20px_rgba(239,68,68,0.2)]' : status === 'scanning' ? 'border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.1)]' : 'border-neutral-800 hover:border-neutral-700'}`}
                >
                  <div className="flex items-center justify-between">
                    <div className={`p-2 rounded-lg transition-colors ${status === 'passed' ? 'bg-green-500/10 text-green-500' : status === 'failed' ? 'bg-red-500/10 text-red-500' : status === 'scanning' ? 'bg-cyan-500/10 text-cyan-400' : 'bg-neutral-800 text-neutral-400'}`}>
                      <mod.icon className="w-5 h-5" />
                    </div>
                    {status === 'passed' && <CheckCircle className="w-5 h-5 text-green-500" />}
                    {status === 'failed' && <AlertTriangle className="w-5 h-5 text-red-500" />}
                    {status === 'scanning' && <Activity className="w-5 h-5 text-cyan-400 animate-pulse" />}
                  </div>
                  <h3 className="font-semibold text-sm text-neutral-200">{mod.name}</h3>
                  <div className="mt-auto">
                    <span className={`text-xs font-medium px-2 py-1 rounded-md ${status === 'passed' ? 'bg-green-500/10 text-green-500' : status === 'failed' ? 'bg-red-500/10 text-red-500' : status === 'scanning' ? 'bg-cyan-500/10 text-cyan-400' : 'bg-neutral-800 text-neutral-500'}`}>
                      {status === 'pending' ? 'Menunggu' : status === 'scanning' ? 'Memindai...' : status === 'passed' ? 'Aman' : 'Rentan'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
          <motion.div 
            whileHover={{ scale: 1.02 }}
            className={`p-6 bg-neutral-900 border rounded-xl flex items-center gap-4 transition-colors ${scanStats.score > 0 ? (scanStats.score >= 80 ? 'border-green-500/50' : scanStats.score >= 50 ? 'border-yellow-500/50' : 'border-red-500/50') : 'border-neutral-800 hover:border-cyan-500/50'}`}
          >
            <div className="p-4 bg-neutral-800 rounded-lg">
              <Shield className={`w-8 h-8 ${scanStats.score > 0 ? (scanStats.score >= 80 ? 'text-green-500' : scanStats.score >= 50 ? 'text-yellow-500' : 'text-red-500') : 'text-cyan-400'}`} />
            </div>
            <div>
              <p className="text-neutral-400 text-sm">Skor Keamanan</p>
              <p className="text-3xl font-bold">
                {scanStats.score > 0 ? scanStats.score : '--'}
                <span className="text-lg text-neutral-500">/100</span>
              </p>
            </div>
          </motion.div>

          <motion.div 
            whileHover={{ scale: 1.02 }}
            className={`p-6 bg-neutral-900 border rounded-xl flex items-center gap-4 transition-colors ${scanStats.vulnerabilities > 0 ? 'border-red-500/50' : 'border-neutral-800 hover:border-red-500/50'}`}
          >
            <div className="p-4 bg-neutral-800 rounded-lg">
              <AlertTriangle className={`w-8 h-8 ${scanStats.vulnerabilities > 0 ? 'text-red-500' : 'text-neutral-500'}`} />
            </div>
            <div>
              <p className="text-neutral-400 text-sm">Kerentanan</p>
              <p className="text-3xl font-bold">{scanStats.score > 0 ? scanStats.vulnerabilities : '--'}</p>
            </div>
          </motion.div>

          <motion.div 
            whileHover={{ scale: 1.02 }}
            className="p-6 bg-neutral-900 border border-neutral-800 rounded-xl flex items-center gap-4 hover:border-green-500/50 transition-colors"
          >
            <div className="p-4 bg-neutral-800 rounded-lg">
              <CheckCircle className="w-8 h-8 text-green-500" />
            </div>
            <div>
              <p className="text-neutral-400 text-sm">Halaman Dipindai</p>
              <p className="text-3xl font-bold">{scanStats.score > 0 ? scanStats.pagesScanned : '--'}</p>
            </div>
          </motion.div>
        </div>

      </main>

      {/* Module Details Modal */}
      <AnimatePresence>
        {selectedModule && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-neutral-900 border border-neutral-700 rounded-2xl w-full max-w-lg p-6 shadow-2xl relative"
            >
              <button 
                onClick={() => setSelectedModule(null)}
                className="absolute top-4 right-4 text-neutral-400 hover:text-white"
              >
                <X className="w-6 h-6" />
              </button>
              
              {(() => {
                const mod = SCAN_MODULES.find(m => m.id === selectedModule);
                const status = moduleStatus[selectedModule] || 'pending';
                const modFindings = findings.filter(f => f.moduleId === selectedModule);
                
                return (
                  <>
                    <div className="flex items-center gap-4 mb-6">
                      <div className={`p-3 rounded-xl ${status === 'passed' ? 'bg-green-500/20 text-green-500' : status === 'failed' ? 'bg-red-500/20 text-red-500' : status === 'scanning' ? 'bg-cyan-500/20 text-cyan-400' : 'bg-neutral-800 text-neutral-400'}`}>
                        {mod && <mod.icon className="w-8 h-8" />}
                      </div>
                      <div>
                        <h2 className="text-xl font-bold">{mod?.name}</h2>
                        <p className="text-sm text-neutral-400">
                          Status: <span className="font-semibold text-white capitalize">{status === 'pending' ? 'Menunggu' : status === 'scanning' ? 'Memindai...' : status === 'passed' ? 'Aman' : 'Rentan'}</span>
                        </p>
                      </div>
                    </div>
                    
                    <div className="bg-neutral-950 rounded-xl p-4 border border-neutral-800 h-64 overflow-y-auto">
                      <h3 className="font-semibold text-neutral-300 mb-3 border-b border-neutral-800 pb-2">Detail Pindaian</h3>
                      
                      {status === 'pending' && <p className="text-neutral-500">Modul belum memulai pemindaian.</p>}
                      {status === 'scanning' && <p className="text-cyan-400 animate-pulse">Pemindaian berlangsung... menganalisis target...</p>}
                      
                      {(status === 'passed' || status === 'failed') && (
                        <div className="space-y-4">
                          <p className="text-sm text-neutral-300">
                            Modul telah selesai dieksekusi.
                          </p>
                          
                          {modFindings.length > 0 ? (
                            <div>
                              <p className="text-sm font-medium text-red-400 mb-2">Kerentanan Ditemukan:</p>
                              <ul className="space-y-2">
                                {modFindings.map((finding, idx) => (
                                  <li key={idx} className="bg-red-500/10 border border-red-500/20 p-3 rounded-lg text-sm">
                                    <div className="flex justify-between items-start mb-1">
                                      <span className="font-semibold text-red-300">{finding.type}</span>
                                      <span className="text-xs px-2 py-0.5 bg-red-500/20 text-red-400 rounded uppercase">{finding.severity}</span>
                                    </div>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          ) : (
                            <div className="flex items-start gap-3 text-green-400 bg-green-500/10 p-4 rounded-lg border border-green-500/20">
                              <CheckCircle className="w-5 h-5 mt-0.5 shrink-0" />
                              <div className="flex flex-col">
                                <span className="font-bold text-base mb-1 text-green-500">Aman Terlindungi</span>
                                <span className="text-sm leading-relaxed text-green-100">{mod ? getSuccessExplanation(mod.id) : ''}</span>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </>
                );
              })()}
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
