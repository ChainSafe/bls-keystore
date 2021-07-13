const NodePolyfillPlugin = require("node-polyfill-webpack-plugin")

module.exports = {
  entry: "./src/web.ts",
  mode: "production",
  output: {
    filename: "bundle.js"
  },
  devtool: "source-map",
  resolve: {
    extensions: [".ts", ".js"],
    fallback: {
      "stream": require.resolve("stream-browserify"),
    }
  },
  module: {
    rules: [
      {test: /\.ts$/, use: {loader: "ts-loader", options: {transpileOnly: true}}}
    ]
  },
  plugins: [
    new NodePolyfillPlugin()
  ]
};
