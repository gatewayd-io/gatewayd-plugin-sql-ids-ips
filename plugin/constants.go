package plugin

const (
	DecodedQueryField string = "decodedQuery"
	DetectorField     string = "detector"
	ScoreField        string = "score"
	QueryField        string = "query"
	ErrorField        string = "error"
	IsInjectionField  string = "is_injection"
	ResponseField     string = "response"
	OutputsField      string = "outputs"
	TokensField       string = "tokens"
	StringField       string = "String"
	ResponseTypeField string = "response_type"

	DeepLearningModel string = "deep_learning_model"
	Libinjection      string = "libinjection"

	ResponseType  string = "error"
	ErrorSeverity string = "EXCEPTION"
	ErrorNumber   string = "42000"
	ErrorMessage  string = "SQL injection detected"
	ErrorDetail   string = "Back off, you're not welcome here."
	LogLevel      string = "error"

	TokenizeAndSequencePath string = "/tokenize_and_sequence"
	PredictPath             string = "/v1/models/%s/versions/%s:predict"
)
