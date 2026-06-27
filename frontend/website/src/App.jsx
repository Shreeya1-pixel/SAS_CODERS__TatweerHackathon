import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ToastProvider } from "./components/Toast";
import Layout from "./components/Layout";
import Home from "./pages/Home";
import Dashboard from "./pages/Dashboard";
import Connect from "./pages/Connect";
import Logs from "./pages/Logs";

import WhatsappDemo from "./pages/WhatsappDemo";
import RiskAssessment from "./pages/RiskAssessment";
import WebScanner from "./pages/WebScanner";
import "./styles/safeo.css";

export default function App() {
  return (
    <ToastProvider>
      <BrowserRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/dashboard" element={<Dashboard />} />

            <Route path="/whatsapp-demo" element={<WhatsappDemo />} />
            <Route path="/risk" element={<RiskAssessment />} />
            <Route path="/scan/website" element={<WebScanner />} />
            <Route path="/connect" element={<Connect />} />
            <Route path="/logs" element={<Logs />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </ToastProvider>
  );
}
