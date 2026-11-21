const repository = "https://github.com/VictorBoykoV/rookstride";
const version = "0.4.0-alpha6";
const assets = `${repository}/releases/download/v${version}`;
const arm64Filename = `rookstride-${version}-arm64.apk`;

export const androidRelease = {
  repository,
  page: `${repository}/releases/tag/v${version}`,
  arm64: {
    filename: arm64Filename,
    sitePath: `/downloads/${arm64Filename}`,
    github: `${assets}/${arm64Filename}`,
    bytes: 69578834,
    sha256: "fb75fcde8b6ba21f54ced592f9fd039939836c6669a8c9456280db9c35b32bce",
  },
  universal: `${assets}/rookstride-${version}-universal.apk`,
};
