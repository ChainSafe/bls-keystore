module.exports = {
  entry: "./src/web.ts",
  mode: "production",
  output: {
    hashFunction: 'xxhash64',
    filename: "bundle.js"
  },
  devtool: "source-map",
  resolve: {
    extensions: [".ts", ".js"]
  },
  module: {
    rules: [
      {test: /\.ts$/, use: {loader: "ts-loader", options: {transpileOnly: true}}}
    ]
  }
};
