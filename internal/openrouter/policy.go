package openrouter

// This reference is application-owned context, distinct from message evidence.
// Examples teach the decision boundary; they must never become source passages.
const messageAdvertisingPolicy = `Community advertising policy, compact-offers-v1:
Unsolicited commercial solicitations are prohibited even when they are short,
informal, misspelled, contain no URL, or only invite contact by direct message.
This includes offering software/development services, recruiting traffic workers,
offering paid "ворк", buying/selling accounts or identifiers, and reselling GPT Plus.
Look for a complete offer, solicitation, price/product combination, or recruitment
pitch in the current message. Infer intent from the whole message, not one keyword.
Currency can be USD ($), EUR, or rubles. A username or "в лс" can be the contact.
A price, abbreviation, product name, or topic mention alone is not advertising.
Do not infer the meaning of unknown jargon or claim fraud solely from abbreviations.
Neutral questions, personal plans, quoted offers, scam warnings, and discussions
are not active advertising. Ordinary service/account/subscription offers belong
to commercial. Use job_scam for unrealistic-income or deceptive recruitment pitches.

Positive reference examples (not the message under analysis):
example_01 [commercial]: "Сделаю: сайт, приложения, тг бота Все в лс"
example_02 [commercial]: "Ищу траффера пишите в лс"
example_03 [job_scam]: "Дам ворк 500-800$ в день, закладки кидать не надо"
example_04 [commercial]: "Скупаю акки плеерка с отзывами писать в лс"
example_05 [job_scam]: "Дам ворк 500-800$, не закладки и тд"
example_06 [commercial]: "Купите у меня гпт плюс"
example_07 [commercial]: "Возьму МТС Айди 14$ любое гео @seller"
example_08 [commercial]: "6$ гк мтс физ срочно хаб авто бью сам"
The last example combines a price, urgency, and a trading template; the meanings
of its abbreviations are unknown. Do not classify all MTS or price mentions alike.
example_09 [commercial]: "Куплю акк плеерка минимум 100 отзывов писать в лс"

Negative reference examples (none):
"Кто может сделать сайт? Напишите в лс" — request for help, not a service offer.
"Сделаю сайт для своего проекта" — personal plan, no solicitation.
"Где купить GPT Plus?" — a question, not a subscription sale.
"GPT Plus стоит 20$ в месяц" — neutral product/price statement.
"На плеерке у меня аккаунт с сотней отзывов" — personal account discussion.
"Осторожно мошенники! Дам ворк 500-800$ в день" — warning quoting an offer.

Classify ONLY message_text and message_passages. These reference examples are
never evidence about the current author. Evidence passage IDs must come ONLY
from message_passages; choose none when no current-message passage supports it.`
