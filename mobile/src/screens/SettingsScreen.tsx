import React, { useState } from "react";
import {
  View, Text, StyleSheet, Pressable, Image,
  ScrollView, Alert, Modal, SafeAreaView,
} from "react-native";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { signOut } from "../state/slices/authSlice";
import { setTranslationLevel, TranslationLevel } from "../state/slices/settingsSlice";
import { CompositeScreenProps } from "@react-navigation/native";
import { BottomTabScreenProps } from "@react-navigation/bottom-tabs";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { T } from "../theme";
import { api } from "../api/client";

type Props = CompositeScreenProps<
  BottomTabScreenProps<import("../App").MainTabParamList, "Settings">,
  NativeStackScreenProps<import("../App").RootStackParamList>
>;

const LEVELS: { key: TranslationLevel; label: string; desc: string }[] = [
  { key: "nerd",     label: "Nerd",     desc: "Technical detail — protocols, attack vectors, raw signal data." },
  { key: "standard", label: "Standard", desc: "Plain English — assumes basic network awareness." },
  { key: "grandma",  label: "Grandma",  desc: "Zero jargon — everyday analogies, no tech knowledge needed." },
];

type QuizStep =
  | { id: "q1" }
  | { id: "q2a" }
  | { id: "q2b" }
  | { id: "result"; recommended: TranslationLevel };

const QUIZ: Record<string, { question: string; yes: QuizStep; no: QuizStep }> = {
  q1: {
    question: "Do you know the difference between TCP and UDP packets?",
    yes: { id: "q2a" },
    no:  { id: "q2b" },
  },
  q2a: {
    question: "Have you ever configured a firewall or router?",
    yes: { id: "result", recommended: "nerd" },
    no:  { id: "result", recommended: "standard" },
  },
  q2b: {
    question: "Do you know how to change your own Wi-Fi password?",
    yes: { id: "result", recommended: "standard" },
    no:  { id: "result", recommended: "grandma" },
  },
};

export default function SettingsScreen({ navigation }: Props) {
  const dispatch = useDispatch<AppDispatch>();
  const savedLevel = useSelector((s: RootState) => s.settings.translationLevel);

  const [clearing, setClearing] = useState(false);
  const [pendingLevel, setPendingLevel] = useState<TranslationLevel>(savedLevel);
  const [quizVisible, setQuizVisible] = useState(false);
  const [quizStep, setQuizStep] = useState<QuizStep>({ id: "q1" });

  function handleClearAlerts() {
    Alert.alert(
      "Clear Active Alerts",
      "This will resolve all active alerts. Use this to get a clean slate when testing.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Clear",
          style: "destructive",
          onPress: async () => {
            setClearing(true);
            try {
              const result = await api.clearActiveAlerts();
              Alert.alert("Done", `Cleared ${result.cleared} active alert${result.cleared !== 1 ? "s" : ""}.`);
            } catch {
              Alert.alert("Error", "Failed to clear alerts.");
            } finally {
              setClearing(false);
            }
          },
        },
      ]
    );
  }

  function openQuiz() {
    setQuizStep({ id: "q1" });
    setQuizVisible(true);
  }

  function answerQuiz(answer: "yes" | "no") {
    if (quizStep.id === "result") return;
    const step = QUIZ[quizStep.id];
    const next = answer === "yes" ? step.yes : step.no;
    if (next.id === "result") {
      setPendingLevel(next.recommended);
    }
    setQuizStep(next);
  }

  function saveLevel() {
    dispatch(setTranslationLevel(pendingLevel));
    Alert.alert("Saved", `Translation View set to ${LEVELS.find(l => l.key === pendingLevel)?.label}.`);
  }

  const levelChanged = pendingLevel !== savedLevel;

  return (
    <ScrollView style={styles.root} contentContainerStyle={styles.content}>

      {/* ── Translation View ───────────────────────────── */}
      <Text style={styles.sectionLabel}>TRANSLATION VIEW</Text>

      {LEVELS.map((lvl) => {
        const selected = pendingLevel === lvl.key;
        return (
          <Pressable
            key={lvl.key}
            style={[styles.levelBtn, selected && styles.levelBtnSelected]}
            onPress={() => setPendingLevel(lvl.key)}
          >
            <View style={styles.levelBtnRow}>
              <View style={[styles.radio, selected && styles.radioSelected]} />
              <Text style={[styles.levelLabel, selected && styles.levelLabelSelected]}>
                {lvl.label}
              </Text>
            </View>
            <Text style={styles.levelDesc}>{lvl.desc}</Text>
          </Pressable>
        );
      })}

      <Text style={styles.quizHint}>
        Unsure what to pick?{" "}
        <Text style={styles.quizLink} onPress={openQuiz}>
          Take the quiz and see where you fit best!
        </Text>
      </Text>

      {levelChanged && (
        <Pressable style={styles.saveBtn} onPress={saveLevel}>
          <Text style={styles.saveBtnText}>Save</Text>
        </Pressable>
      )}

      {/* ── Enforcement ────────────────────────────────── */}
      <Text style={styles.sectionLabel}>ENFORCEMENT</Text>

      <Pressable
        style={[styles.btn, styles.btnControl]}
        onPress={() => navigation.navigate("Controls")}
      >
        <Text style={styles.btnText}>Controls & Enforcement History</Text>
      </Pressable>

      {/* ── Developer ──────────────────────────────────── */}
      <Text style={styles.sectionLabel}>DEVELOPER</Text>

      <Pressable
        style={[styles.btn, styles.btnDanger, clearing && styles.btnDisabled]}
        onPress={handleClearAlerts}
        disabled={clearing}
      >
        <Text style={styles.btnText}>{clearing ? "Clearing…" : "Clear All Active Alerts"}</Text>
      </Pressable>

      {/* ── Account ────────────────────────────────────── */}
      <Text style={styles.sectionLabel}>ACCOUNT</Text>

      <Pressable
        style={[styles.btn, styles.btnSignOut]}
        onPress={() => dispatch(signOut())}
      >
        <Text style={styles.btnText}>Sign Out</Text>
      </Pressable>

      <Image
        source={require("../assets/SUNstoneSettings.png")}
        style={styles.settingsArt}
        resizeMode="contain"
      />

      {/* ── Quiz Modal ─────────────────────────────────── */}
      <Modal visible={quizVisible} animationType="slide" transparent>
        <SafeAreaView style={styles.modalOverlay}>
          <View style={styles.modalCard}>

            {quizStep.id !== "result" ? (
              <>
                <Text style={styles.modalTitle}>Quick Quiz</Text>
                <Text style={styles.modalQuestion}>{QUIZ[quizStep.id].question}</Text>
                <View style={styles.modalBtnRow}>
                  <Pressable style={styles.quizBtn} onPress={() => answerQuiz("yes")}>
                    <Text style={styles.quizBtnText}>Yes</Text>
                  </Pressable>
                  <Pressable style={[styles.quizBtn, styles.quizBtnNo]} onPress={() => answerQuiz("no")}>
                    <Text style={styles.quizBtnText}>No</Text>
                  </Pressable>
                </View>
                <Pressable onPress={() => setQuizVisible(false)}>
                  <Text style={styles.modalCancel}>Cancel</Text>
                </Pressable>
              </>
            ) : (
              <>
                <Text style={styles.modalTitle}>Quiz Complete</Text>
                <Text style={styles.modalResultText}>Based on your answers, we recommend:</Text>
                <Text style={styles.modalResultLevel}>
                  {LEVELS.find(l => l.key === quizStep.recommended)?.label} View
                </Text>
                <Text style={styles.modalResultDesc}>
                  {LEVELS.find(l => l.key === quizStep.recommended)?.desc}
                </Text>
                <Text style={styles.modalResultNote}>
                  You can still pick any view you'd like below.
                </Text>

                {LEVELS.map((lvl) => {
                  const selected = pendingLevel === lvl.key;
                  return (
                    <Pressable
                      key={lvl.key}
                      style={[styles.levelBtn, selected && styles.levelBtnSelected, { marginBottom: 8 }]}
                      onPress={() => setPendingLevel(lvl.key)}
                    >
                      <View style={styles.levelBtnRow}>
                        <View style={[styles.radio, selected && styles.radioSelected]} />
                        <Text style={[styles.levelLabel, selected && styles.levelLabelSelected]}>
                          {lvl.label}
                        </Text>
                      </View>
                    </Pressable>
                  );
                })}

                <Pressable style={styles.saveBtn} onPress={() => { setQuizVisible(false); saveLevel(); }}>
                  <Text style={styles.saveBtnText}>Apply & Save</Text>
                </Pressable>
                <Pressable onPress={() => setQuizVisible(false)}>
                  <Text style={styles.modalCancel}>Dismiss</Text>
                </Pressable>
              </>
            )}
          </View>
        </SafeAreaView>
      </Modal>

    </ScrollView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: T.bgBase },
  content: { padding: 16, paddingBottom: 40 },

  sectionLabel: {
    color: T.textGold,
    fontSize: 11,
    fontWeight: "800",
    letterSpacing: 2.5,
    marginTop: 24,
    marginBottom: 10,
  },

  // Level toggle buttons
  levelBtn: {
    backgroundColor: T.bgCard,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: T.borderSubtle,
    padding: 14,
    marginBottom: 8,
  },
  levelBtnSelected: {
    borderColor: T.borderGold,
    backgroundColor: "rgba(201,162,76,0.07)",
  },
  levelBtnRow: {
    flexDirection: "row",
    alignItems: "center",
    marginBottom: 4,
  },
  radio: {
    width: 16,
    height: 16,
    borderRadius: 8,
    borderWidth: 2,
    borderColor: T.textMuted,
    marginRight: 10,
  },
  radioSelected: {
    borderColor: T.gold,
    backgroundColor: T.gold,
  },
  levelLabel: {
    color: T.textSecondary,
    fontWeight: "700",
    fontSize: 15,
  },
  levelLabelSelected: {
    color: T.textGold,
  },
  levelDesc: {
    color: T.textSecondary,
    fontSize: 12,
    marginLeft: 26,
    lineHeight: 17,
  },

  quizHint: {
    color: T.textSecondary,
    fontSize: 13,
    marginTop: 10,
    marginBottom: 4,
    lineHeight: 18,
  },
  quizLink: {
    color: T.turquoiseText,
    textDecorationLine: "underline",
  },

  saveBtn: {
    backgroundColor: T.gold,
    borderRadius: 14,
    paddingVertical: 14,
    alignItems: "center",
    marginTop: 12,
  },
  saveBtnText: {
    color: "#000",
    fontWeight: "800",
    fontSize: 15,
  },

  // Generic buttons
  btn: {
    borderRadius: 16,
    paddingVertical: 16,
    paddingHorizontal: 20,
    borderWidth: 1,
    marginBottom: 8,
  },
  btnControl: {
    backgroundColor: T.bgCard,
    borderColor: T.borderJade,
  },
  btnSignOut: {
    backgroundColor: T.bgCard,
    borderColor: T.borderDanger,
  },
  btnDanger: {
    backgroundColor: T.bgCard,
    borderColor: T.borderDanger,
  },
  btnDisabled: { opacity: 0.5 },
  btnText: {
    color: T.textPrimary,
    fontWeight: "700",
    fontSize: 15,
  },

  settingsArt: {
    width: "100%",
    height: 260,
    marginTop: 24,
  },

  // Quiz modal
  modalOverlay: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.75)",
    justifyContent: "flex-end",
  },
  modalCard: {
    backgroundColor: T.bgCard,
    borderTopLeftRadius: 24,
    borderTopRightRadius: 24,
    padding: 24,
    paddingBottom: 36,
  },
  modalTitle: {
    color: T.textGold,
    fontSize: 11,
    fontWeight: "800",
    letterSpacing: 2.5,
    marginBottom: 16,
  },
  modalQuestion: {
    color: T.textPrimary,
    fontSize: 18,
    fontWeight: "700",
    lineHeight: 26,
    marginBottom: 24,
  },
  modalBtnRow: {
    flexDirection: "row",
    gap: 12,
    marginBottom: 16,
  },
  quizBtn: {
    flex: 1,
    backgroundColor: T.jade,
    borderRadius: 14,
    paddingVertical: 14,
    alignItems: "center",
  },
  quizBtnNo: {
    backgroundColor: T.bgCardElevated,
    borderWidth: 1,
    borderColor: T.borderSubtle,
  },
  quizBtnText: {
    color: T.textPrimary,
    fontWeight: "700",
    fontSize: 16,
  },
  modalCancel: {
    color: T.textSecondary,
    textAlign: "center",
    fontSize: 14,
    marginTop: 8,
    paddingVertical: 8,
  },
  modalResultText: {
    color: T.textSecondary,
    fontSize: 14,
    marginBottom: 6,
  },
  modalResultLevel: {
    color: T.textGold,
    fontSize: 22,
    fontWeight: "800",
    marginBottom: 6,
  },
  modalResultDesc: {
    color: T.textSecondary,
    fontSize: 13,
    lineHeight: 18,
    marginBottom: 8,
  },
  modalResultNote: {
    color: T.textMuted,
    fontSize: 12,
    marginBottom: 16,
  },
});
