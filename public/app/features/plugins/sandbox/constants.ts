export const forbiddenElements = ['iframe'];

// script elements can still be created because webpack chunk loading creates them and hands them to
// appendChild, which evaluates them inside the sandbox instead of inserting them into the document.
export const forbiddenInsertedElements = [...forbiddenElements, 'script'];
