import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  reactStrictMode: true,
  turbopack: {
    root: path.resolve(__dirname, ".."),
  },
  webpack: (config) => {
    config.ignoreWarnings = [
      ...(config.ignoreWarnings ?? []),
      {
        module: /node_modules\/web-worker\/cjs\/node\.js/,
        message: /Critical dependency: the request of a dependency is an expression/,
      },
    ];

    return config;
  },
};

export default nextConfig
