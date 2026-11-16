import { PageHeader } from "@/components/Layout";
import { Card, CardContent } from "@/components/ui/card";
import type { NavItem } from "@/navigation";

export function Planned({ item }: { item: NavItem }) {
  return (
    <>
      <PageHeader title={item.label} description={item.summary ?? ""} />
      <Card>
        <CardContent className="p-8 text-center text-sm text-muted-foreground">
          Ten widok dostanie dane w Etapie {item.stage}. Szkielet aplikacji, inwentarz, zakres i
          dziennik audytu działają już teraz.
        </CardContent>
      </Card>
    </>
  );
}
