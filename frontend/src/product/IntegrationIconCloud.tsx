import { useMemo, type CanvasHTMLAttributes } from "react";
import { Cloud, renderSimpleIcon } from "react-icon-cloud";
import {
  siDatadog,
  siDocker,
  siGithub,
  siGitlab,
  siGrafana,
  siJira,
  siKubernetes,
  siNeo4j,
  siPostgresql,
  siPrometheus,
  siSplunk,
  siTerraform,
  type SimpleIcon,
} from "simple-icons";
import { useTheme } from "../theme";

const ecosystemIcons: SimpleIcon[] = [
  siGithub,
  siGitlab,
  siJira,
  siSplunk,
  siDatadog,
  siKubernetes,
  siDocker,
  siTerraform,
  siPrometheus,
  siGrafana,
  siPostgresql,
  siNeo4j,
];

export const integrationIcons: Record<string, SimpleIcon | undefined> = {
  Jira: siJira,
  Splunk: siSplunk,
  GitHub: siGithub,
  GitLab: siGitlab,
};

export function IntegrationBrandIcon({ name }: { name: string }) {
  const icon = integrationIcons[name];
  if (!icon) return <>{name.slice(0, 2)}</>;
  return (
    <svg viewBox="0 0 24 24" role="img" aria-label={`${name} logo`}>
      <path d={icon.path} fill="currentColor" />
    </svg>
  );
}

export function IntegrationIconCloud({
  onSelect,
}: {
  onSelect: (name: string) => void;
}) {
  const { theme } = useTheme();
  const reducedMotion = window.matchMedia(
    "(prefers-reduced-motion: reduce)",
  ).matches;
  const background = theme === "dark" ? "#0d1b25" : "#fafdff";
  const fallback = theme === "dark" ? "#d5edf8" : "#163b4d";
  const icons = useMemo(
    () =>
      ecosystemIcons.map((icon) =>
        renderSimpleIcon({
          icon,
          size: 44,
          bgHex: background,
          fallbackHex: fallback,
          minContrastRatio: 2.5,
          aProps: {
            onClick: (event) => {
              event.preventDefault();
              onSelect(icon.title);
            },
            title: `Configure ${icon.title}`,
          },
          imgProps: {
            alt: icon.title,
          },
        }),
      ),
    [background, fallback, onSelect],
  );
  const canvasProps: CanvasHTMLAttributes<HTMLCanvasElement> = {
    "aria-label": "Interactive cloud of supported security integrations",
    role: "img",
    width: 440,
    height: 440,
    style: { width: "100%", maxWidth: 390, height: "auto" },
  };

  return (
    <div className="cs-icon-cloud">
      <Cloud
        id={`cloudsentinel-integrations-${theme}`}
        options={{
          clickToFront: 450,
          depth: 0.82,
          dragControl: true,
          freezeActive: true,
          initial: reducedMotion ? [0, 0] : [0.035, -0.018],
          maxSpeed: reducedMotion ? 0 : 0.035,
          minSpeed: reducedMotion ? 0 : 0.004,
          noMouse: reducedMotion,
          outlineColour: theme === "dark" ? "#8dd9f7" : "#146b8d",
          outlineMethod: "outline",
          outlineThickness: 1,
          reverse: true,
          shuffleTags: false,
          tooltip: "native",
          wheelZoom: false,
          zoom: 0.86,
        }}
        canvasProps={canvasProps}
        containerProps={{ className: "cs-icon-cloud-canvas" }}
      >
        {icons}
      </Cloud>
      <div className="cs-icon-cloud-actions" aria-label="Integration shortcuts">
        {ecosystemIcons.slice(0, 6).map((icon) => (
          <button key={icon.slug} type="button" onClick={() => onSelect(icon.title)}>
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d={icon.path} fill="currentColor" />
            </svg>
            {icon.title}
          </button>
        ))}
      </div>
    </div>
  );
}
