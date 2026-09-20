package evaluation

import (
	"antispambee/internal/detection"
	"antispambee/internal/moderation"
	"os"
	"strings"
	"testing"
)

func TestMetricsCountBothKindsOfError(t *testing.T) {
	ad := "Ищем сотрудников, удаленная работа, 5000 рублей в день, пишите в лс"
	r, err := Evaluate([]Example{example("tp", "spam", ad), example("fp", "ham", ad), example("fn", "spam", "неизвестный обход"), example("tn", "ham", "Привет")}, "test", "rules", false)
	if err != nil {
		t.Fatal(err)
	}
	if r.TP != 1 || r.FP != 1 || r.FN != 1 || r.TN != 1 || r.Precision == nil || *r.Precision != .5 || r.Recall == nil || *r.Recall != .5 || r.Precision95Lower == nil || *r.Precision95Lower >= .5 {
		t.Fatalf("wrong metrics: %+v", r)
	}
	if len(r.FalsePositiveIDs) != 1 || r.FalsePositiveIDs[0] != "fp" || r.FalseNegativeIDs[0] != "fn" {
		t.Fatal("wrong error IDs")
	}
}

func TestReadRejectsMalformedAndOversizedRows(t *testing.T) {
	for _, input := range []string{"{", strings.Repeat("x", 2<<20)} {
		if _, err := Read(strings.NewReader(input)); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
}

func TestReplayRejectsOldModelAndUnlabeledData(t *testing.T) {
	e := example("old", "spam", "Реклама")
	e.Evidence.Signals = []detection.Signal{{Detector: "model.jev_advertising", DetectorVersion: "jev-message-v2"}}
	if _, err := Evaluate([]Example{e}, "test", "replay", false); err == nil {
		t.Fatal("old model replayed as current")
	}
	e.Label = "unlabeled"
	if _, err := Evaluate([]Example{e}, "test", "rules", false); err == nil {
		t.Fatal("machine outcome used as label")
	}
}

func TestSyntheticRegressionCorpus(t *testing.T) {
	f, err := os.Open("testdata/synthetic.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	examples, err := Read(f)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Evaluate(examples, "test", "rules", false)
	if err != nil {
		t.Fatal(err)
	}
	if r.FP != 0 || r.FN != 0 || r.TP != 6 || r.TN != 9 {
		t.Fatalf("synthetic regression: %+v", r)
	}
}

func example(id, label, text string) Example {
	return Example{ID: id, Label: label, Split: "test", Campaign: id, Source: "synthetic", Evidence: moderation.Evidence{Message: detection.MessageContent{Text: text}}}
}

func TestMetricsIncludeFalseNegativesAndUndefinedPrecision(t *testing.T) {
	r, err := Evaluate([]Example{example("a", "ham", "Привет"), example("b", "spam", "обход неизвестный"), example("c", "uncertain", "спорно")}, "test", "rules", false)
	if err != nil {
		t.Fatal(err)
	}
	if r.FN != 1 || r.TN != 1 || r.Precision != nil || r.Recall == nil || *r.Recall != 0 || r.Uncertain != 1 {
		t.Fatalf("wrong report: %+v", r)
	}
}

func TestDatasetRejectsDuplicateAndCampaignLeakage(t *testing.T) {
	a := example("a", "ham", "Привет")
	b := a
	b.ID = "b"
	b.Split = "dev"
	for _, examples := range [][]Example{{a, a}, {a, b}} {
		if _, err := Evaluate(examples, "test", "rules", false); err == nil {
			t.Fatal("accepted contaminated dataset")
		}
	}
}

func TestRepresentativeEvaluationExcludesBiasedAuditCases(t *testing.T) {
	a := example("a", "ham", "Привет")
	a.Source = "production"
	b := a
	b.ID = "b"
	b.Campaign = "b"
	b.Evidence.EvaluationSample = true
	r, err := Evaluate([]Example{a, b}, "test", "rules", true)
	if err != nil || r.TN != 1 {
		t.Fatalf("report=%+v err=%v", r, err)
	}
}
