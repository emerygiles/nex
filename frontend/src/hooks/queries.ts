import { useQuery } from "@tanstack/react-query";
import { getCoverage, getHealth } from "../lib/api";

/** Backend health (data plane, brain, mode). */
export function useHealth() {
  return useQuery({ queryKey: ["health"], queryFn: getHealth, refetchOnWindowFocus: false, staleTime: 10_000 });
}

/** Current environment + coverage snapshot. Invalidate after a run to reflect new detections. */
export function useCoverage() {
  return useQuery({ queryKey: ["coverage"], queryFn: getCoverage, refetchOnWindowFocus: false });
}
