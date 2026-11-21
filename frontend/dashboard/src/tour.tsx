import { GraduationCap } from "lucide-react";
import { useCallback, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";

import { runTour, wasDone } from "@/tour-steps";
import { Button } from "@shared/components/ui/button";
import { isDemoRecording } from "@shared/lib/demo";
import { useAuth } from "@shared/lib/auth-context";

/** Przycisk „Samouczek” w nagłówku i automatyczny start przy pierwszym logowaniu. */
export function TourButton() {
  const navigate = useNavigate();
  const { me } = useAuth();
  const user = me?.username;
  const started = useRef(false);
  const start = useCallback(() => {
    if (user) runTour(navigate, user);
  }, [navigate, user]);
  useEffect(() => {
    if (!user || started.current || wasDone(user)) return;
    // Tryb nagrywania demo prowadzi własny scenariusz, bez samouczka.
    if (isDemoRecording()) return;
    started.current = true;
    start();
  }, [user, start]);
  return (
    <Button variant="ghost" size="sm" onClick={start} aria-label="Uruchom samouczek">
      <GraduationCap className="size-4" aria-hidden />
      <span className="hidden lg:inline">Samouczek</span>
    </Button>
  );
}
