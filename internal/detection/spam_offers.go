package detection

import "regexp"

const (
	ReasonRecruitmentSpam        = "RECRUITMENT_SPAM"
	ReasonEducationDocumentOffer = "EDUCATIONAL_DOCUMENT_OFFER"

	largePayment = `(?:[1-9][0-9]{3,6}|[1-9][0-9]{0,2} [0-9]{3})`
)

var (
	driverTripPayment  = regexp.MustCompile(`(?i)рейс от ` + largePayment + `(?:[[:punct:] ₽]|$)`)
	recruitmentPayout  = regexp.MustCompile(`(?i)возможность взять [1-9][0-9]? (?:ребят|человек|людей)[,; ]+(?:и )?получите по ` + largePayment + `(?:[[:punct:] ₽]|$)`)
	apartmentPayout    = regexp.MustCompile(`(?i)каждому (?:получится|по) ` + largePayment + `(?:[[:punct:] ₽]|$)`)
	expeditedEducation = regexp.MustCompile(`(?i)за [1-3](?: *[-–—−] *[1-3])? месяц(?:а|ев)?(?:[[:punct:] ]|$)`)
)

func isRecruitmentSpam(numberText, text string, hasContact bool) bool {
	deliveryRecruitment := containsAny(text, "нужны люди для доставк", "ищем людей для доставк",
		"нужны курьеры", "набираем курьеров", "требуются курьеры") &&
		containsAny(text, "за смену", "за рейс") && jobMoneyAmountPattern.MatchString(numberText) &&
		(hasContact || containsAny(text, "интересны детали", "начать можно уже сегодня"))
	paidDriverRecruitment := containsAny(text, "ищу водителя", "ищем водителя") &&
		containsAny(text, "с личным авто", "только с правами") &&
		driverTripPayment.MatchString(numberText) && containsAny(text, "аванс", "компенсация расходов")
	paidApartmentPickup := containsAny(text, "помочь забрать вещи", "помочь вывезти вещи") &&
		containsAny(text, "со съемной квартиры", "из съемной квартиры", "из арендованной квартиры") &&
		apartmentPayout.MatchString(numberText)
	return deliveryRecruitment || paidDriverRecruitment || paidApartmentPickup || recruitmentPayout.MatchString(numberText)
}

func isEducationDocumentOffer(numberText, text string, hasLink bool) bool {
	contact := hasLink || containsAny(text, "пишите в личку", "пишите в лс", "пиши в личку", "пиши в лс", "оформить заказ")
	if !contact {
		return false
	}
	if containsAny(text, "изготовим диплом", "оформим диплом без обучения", "продаем дипломы", "закажите диплом") {
		return true
	}
	if !containsAny(text, "высшее и среднее образование", "высшее образование", "среднее специальное образование", "среднее профессиональное образование", "диплом") {
		return false
	}
	return containsAny(text, "помогаем получить", "поможем получить", "оформим", "оформляем") &&
		(containsAny(text, "без обучения", "без учебы") || expeditedEducation.MatchString(numberText))
}
