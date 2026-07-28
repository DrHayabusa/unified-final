import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import { PlatformProvider } from "./context/PlatformContext.jsx";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <PlatformProvider>
      <App />
    </PlatformProvider>
  </React.StrictMode>,
);
