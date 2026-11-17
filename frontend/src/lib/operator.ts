import { useState } from "react";

import { getOperator, setOperator } from "@/lib/utils";

/** Imię operatora zapamiętane w przeglądarce, dopóki nie ma logowania. */
export function useOperator(): [string, (name: string) => void] {
  const [name, setName] = useState(getOperator);
  return [
    name,
    (value: string) => {
      setName(value);
      setOperator(value);
    },
  ];
}
