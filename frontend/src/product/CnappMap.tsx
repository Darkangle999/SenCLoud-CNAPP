import { useMemo } from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
} from "react-simple-maps";
import { useTheme } from "../theme";
import { assets } from "./data";
import { useProduct } from "./store";

const GEO_URL = "/geo/countries-110m.json";
const regionCoordinates: Record<string, [number, number]> = {
  "us-east-1": [-78.8, 38],
  "eu-west-1": [-6.2, 53],
  "ap-south-1": [72.9, 19.1],
  "ap-southeast-1": [103.8, 1.3],
};

export function CloudWorldMap({
  dataMode = false,
  regions,
}: {
  dataMode?: boolean;
  regions?: Array<{ region: string; total: number; exposed: number }>;
}) {
  const { inScope } = useProduct();
  const { theme } = useTheme();
  const palette = useMemo(
    () =>
      theme === "dark"
        ? {
            grid: "#213746",
            surface: "#0e1e29",
            accent: "#8dd9f7",
            critical: "#ff5f6d",
          }
        : {
            grid: "#a6d5e7",
            surface: "#fafdff",
            accent: "#146b8d",
            critical: "#c93445",
          },
    [theme],
  );
  const demoMarkers = Object.entries(
    assets.filter((asset) => inScope(asset.account, asset.region)).reduce(
      (sum, asset) => {
        if (asset.region !== "Global") {
          const current = sum[asset.region] || { total: 0, exposed: 0 };
          current.total += 1;
          current.exposed += asset.exposure === "Public" ? 1 : 0;
          sum[asset.region] = current;
        }
        return sum;
      },
      {} as Record<string, { total: number; exposed: number }>,
    ),
  ).map(([region, count]) => ({ region, ...count }));
  const markers = regions ?? demoMarkers;
  return (
    <div className="cs-world-map">
      <ComposableMap
        width={860}
        height={330}
        projection="geoEqualEarth"
        projectionConfig={{ scale: 145 }}
        aria-label={
          dataMode
            ? "Sensitive data residency map"
            : "Global asset exposure map"
        }
      >
        <Geographies geography={GEO_URL}>
          {({ geographies }) =>
            geographies.map((geography) => (
              <Geography
                key={geography.rKey}
                geography={geography}
                fill={palette.grid}
                stroke={palette.surface}
                strokeWidth={0.5}
              />
            ))
          }
        </Geographies>
        {markers.map((count) => {
          const position = regionCoordinates[count.region];
          if (!position) return null;
          const risk = dataMode
            ? assets.filter(
                (asset) =>
                  asset.region === count.region &&
                  asset.sensitivity !== "Not classified",
              ).length
            : count.exposed;
          return (
            <Marker key={count.region} coordinates={position}>
              <circle
                r={7 + Math.sqrt(count.total) * 2.2}
                fill={risk ? palette.critical : palette.accent}
                fillOpacity={0.2}
                stroke={risk ? palette.critical : palette.accent}
                strokeWidth={1.2}
              />
              <circle
                r={2.5}
                fill={risk ? palette.critical : palette.accent}
              />
              <title>{`${count.region}: ${count.total} assets, ${risk} ${dataMode ? "sensitive" : "public"}`}</title>
            </Marker>
          );
        })}
      </ComposableMap>
      <div className="cs-map-legend">
        <span>
          <i className="critical" />
          {dataMode ? "Sensitive data" : "Public exposure"}
        </span>
        <span>
          <i />Observed region
        </span>
        <small>Marker size represents resource volume</small>
      </div>
    </div>
  );
}
