import { motion } from "motion/react";
import { useIdioma } from "../i18n";
import type { Revisao } from "../tipos";
import { banda } from "../util";

/** A escala fixa de magnitude: 15 marcas, acesas até o nível da regra. */
export function Magnitude({ nivel }: { nivel: number }) {
  return (
    <span className="magnitude" aria-hidden="true">
      {Array.from({ length: 15 }, (_, i) => (
        <i key={i} className={i < nivel ? "acesa" : undefined} />
      ))}
    </span>
  );
}

/** Bloco designador da faixa: cor pela banda do nível, número grande e a magnitude. */
export function Designador({ nivel, grande = false }: { nivel: number; grande?: boolean }) {
  const { t } = useIdioma();
  return (
    <span
      className={`designador designador--${banda(nivel)}${grande ? " designador--grande" : ""}`}
      aria-label={`${t("nivel")} ${nivel}`}
    >
      <span className="designador__numero" aria-hidden="true">
        {nivel}
      </span>
      <Magnitude nivel={nivel} />
    </span>
  );
}

interface PropsCarimbo {
  revisao: Exclude<Revisao, "pendente">;
  grande?: boolean;
  /** Só a decisão que acabou de acontecer bate o carimbo; as antigas já chegam carimbadas. */
  bater?: boolean;
}

export function Carimbo({ revisao, grande = false, bater = false }: PropsCarimbo) {
  const { rotulo } = useIdioma();
  return (
    <motion.span
      className={`carimbo carimbo--${revisao}${grande ? " carimbo--grande" : ""}`}
      initial={bater ? { scale: 1.5, opacity: 0, rotate: -12 } : false}
      animate={{ scale: 1, opacity: 1, rotate: -4 }}
      transition={{ type: "spring", stiffness: 520, damping: 22 }}
    >
      {rotulo("carimbo", revisao)}
    </motion.span>
  );
}
