const webpack = require("webpack");
const path = require("path");
const buildPath = path.join(__dirname, "./wwwroot/content");
const {CleanWebpackPlugin} = require("clean-webpack-plugin");
const CopyWebpackPlugin = require("copy-webpack-plugin");
const MiniCssExtractPlugin = require("mini-css-extract-plugin");
const CssMinimizerPlugin = require("css-minimizer-webpack-plugin");
// from webpack 5 to minify js
const TerserPlugin = require("terser-webpack-plugin");
module.exports = {
    mode: "production",
    entry: {
        app: "./Content/js/index.js",
    },
    output: {
        path: buildPath,
        publicPath: "/content/",
        filename: "[name].min.js"
    },
    target: ["web", "es5"],
    module: {
        rules: [
            {
                mimetype: 'image/svg+xml',
                scheme: 'data',
                type: 'asset/resource',
                generator: {
                    filename: 'icons/[hash].svg'
                }
            },
            {
                test: /\.m?(js)$/,
                exclude: /(Content\/static|Content\\static)/i,
                use: {
                    loader: "babel-loader",
                    options: {
                        presets: [
                            [
                                "@babel/preset-env",
                                {
                                    "targets": {
                                        "chrome": 22,
                                        "ios": 9,
                                        "ie": 11
                                    },
                                    "forceAllTransforms": true
                                }
                            ]
                        ]
                    }
                }
            },
            {
                test: /\.(otf|png|jpe?g|svg|woff|woff2|eot|ttf|gif)(\?\S*)?$/,
                type: "asset/resource",
                generator: {
                    filename: "[name][ext]"
                }
            },
            {
                test: /\.(scss)$/,
                use: [
                    {
                        loader: MiniCssExtractPlugin.loader,
                    },
                    {
                        loader: "css-loader",
                        options: {
                            sourceMap: true,
                            importLoaders: 2
                        }
                    },
                    {
                        loader: 'postcss-loader',
                        options: {
                            postcssOptions: {
                                plugins: () => [
                                    require('autoprefixer')
                                ]
                            }
                        }
                    },
                    {
                        loader: 'sass-loader'
                    }
                ]
            }
        ]
    },
    plugins: [
        new webpack.ProgressPlugin(),
        new CleanWebpackPlugin(
            {
                verbose: true,
                dry: false
            }),
        new CopyWebpackPlugin({
            patterns: [
                {
                    from: "**/*.(png|svg|jpg|js|ico)",
                    globOptions: {
                        dot: false
                    },
                    to: "../static/",
                    context: "Content/static"
                }
            ]
        }),

        new MiniCssExtractPlugin({
            filename: "[name].min.css"
        })
    ],
    optimization: {
        minimize: true,
        minimizer: [
            new CssMinimizerPlugin(
                {
                    minimizerOptions: {
                        preset: [
                            "default",
                            {
                                discardComments: {removeAll: true},
                                discardDuplicates: true,
                                mergeLonghand: true,
                                mergeRules: true
                            },
                        ],
                    },
                }
            ),
            new TerserPlugin({
                test: /\.min\.js$/,
                exclude: /(static)/i,
            }),
        ],
        splitChunks: {
            cacheGroups: {
                default: false,
                commons: {
                    test: /[\\/]node_modules[\\/]/,
                    name: "vendor",
                    chunks: "all"
                }
            }
        }
    },
    devtool: false
};
