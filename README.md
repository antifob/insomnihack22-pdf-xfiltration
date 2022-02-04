# Insomni'hack Teaser CTF 2022 - PDF Xfiltration

**This writeup is written after the event ended.**

```
Try to steal data from Dr. Virus to understand what's happening to your brother.

link: http://pdfxfiltration.insomnihack.ch
```

## Problem statement

Essentially, Dr. Virus sent an encrypted PDF to one of their patient. Our task
is to recover its content. To do so, our malicious PDF will be sent to a server
and opened by Dr. Virus in a specific version of a PDF editor.


## Solving

That challenge was brought late in the event by my teammates @klammydia and
@nic-lovin. At that point, they were convinced of the attack vector and had
a semi-PoC going on, and were hoping to get some help solving the challenge.

They presented their progress and the https://www.pdf-insecurity.org/index.html
site which describes attacks on encrypted PDFs. The PoC consisted in a PDF
containing a JavaScript payload written with the target PDF editor. The job
was presented as taking the payload and transferring it to the challenge PDF.
The challenge piqued my interest so I started working on it.

I wasn't really familiar with the structure of PDFs. I knew it could be written
by hand, the structure was conceptually simple, but the nitty gritty details
were somethings I never really looked into. Anyway, after a bit of analysis and
playing around with the exploit examples of the above-mentioned website, I
figured that sending the exploit `A3-script_08-stm-eff-false.pdf` to the
challenge's website would be a good, concrete, step. Upon submission, the
website rejected the PDF stating it had content flagged as malicious. All
right... and removing the JavaScript payload didn't help. Something related
to annotations (`/Annot`) was also causing the website to reject the payload.
Also, sending my teammate's PoC to the website worked. We could exfiltrate
content and read arbitrary files, but that didn't really help us solve the
challenge so I was back to where my teammates were.

Looking at my teammate's PDF, the JavaScript payload was compressed and that
was probably why the WAF didn't block it. However, PDFs are quite complex and
that one had a bunch of objects embedded in the compressed stream. Also,
our tooling, up to that point, was to manually craft PDFs and add an ASCII
`xref` section at the end. The more I dug in, trying to see how I can extract
an object from one PDF and insert it into another without making the PDF
invalid, the more I realized I didn't know enough about PDFs. At one point,
after 20 hours of doing challenges, everyone got tired, we called it quit and
the CTF ended.

Only 2 teams managed to solve the challenge during the event so we weren't
sad about it. The challenge was definitely a non-obvious one. They published


The next day, I went on to read the write-ups of the two (2) teams that solved
the challenge knowing I'll learn something cool. Their solutions were quite
similar, but none the same as mine. Essentially, they went with a quite
direct path to JavaScript execution and the remaining challenge was how to
extract the content with an `/EmbeddedFiles` entry. My approach was more
aligned with: I'll create a PDF with a payload that the WAF is going to be
completely oblivious to we'll win. For that, I'd compress an `/Annot` and
a `/JavaScript` object inside a `/ObjStm` object.

To do that, I started analyzing the PDF-insecurity project's PoC, my
teammate's and the challenge's PDFs. I also dug out various PDF
specification documents to provide factual definitions. I also took a look
at Ange Albertini's always awesome work and, in this case, its crafted PDFs.
In the process, here are the take aways:

- An `/ObjStm` has a header that specifies the offset of the objects that
  follow.
- You can't use a plain ASCII `xref` section when using `/ObjStm`; the
  PDF reader's going to complain that some objects are missing when the
  PDF refers to objects inside the `/ObjStm`.
- When an `/ObjStm` is used, the `xref` needs to be in the compressed/binary
  format.
- Objects can be encoded with DEFLATE (`/FlateEncode`),
  ascii85 (`/ASCII85Encode`) or hexadecimal (`/ASCIIHexEncode`). The latter
  two (2) are much nicer to work with when crafting a PDF in a text editor. :)

In the process, I started with a bare-bone PDF and manually adding objects,
encoding them and re-structuring the PDF and adding objects and ... it worked...
kind of. An assumption we had was that the content could be exfiltrated
with an `/Annot` object, but it didn't work with the challenge's PDF.
You see, the `/Annot` method doesn't work for binary (or maybe it's
just `/FlateDecode` objects) ciphertexts. I had to go back to the write-ups
and use the `/EmbeddedFiles` object to make it work... Finally! :tada:
After looking the PDF-insecurity project's PoCs, that technique is used
in the PDF right beside the one I had worked with from the beginning.

Anyway, I'm pretty proud of the end result. Essentially, it's possible to
craft a base PDF that has only two (2) objects: the ciphertext object and
the cipher statement object. With these, one can add a `/ObjStm` object
that contains pretty much everything else that makes the document (`/Catalog`,
`/Pages`, `/Page`, text, formatting, etc.), but, more importantly, a payload
that exfiltrates the encrypted message. :)

In this repository you'll find a script that takes a barebone PDF composed
of two (2) such objects and that will append a payload that exfiltrate
the content. It works for the targeted known-vulnerable software, so with
the PDF-insecurity project's PoC and and the challenge's PDFs. The resulting
PDF is a blank page, but there's nothing preventing from show a nice-looking
page that's less suspicious.

**A teammate went to the organizer and asked the challenge PDF's password.
This allowed me to test my solution. Here's the password: `UvQvllwUvQvllw9q+/qrf,u9q+/qrf,u`**


## Conclusion

After my initial look at the write-ups, I knew full well that my solution
was more complicated. However, I wanted to test my initial solution and
show myself that it was possible. The lack of knowledge around PDFs was a
major issue for that challenge and I couldn't find PDF tooling that is
surgical enough. Anyway, being able to make the PDF so bare-looking that
it would fool any dumb WAF was another goal of continuing this research;
security products and analysts should definitely look at `/ObjStm` objects
:P

A big thank you to the author and the Insomni'hack team for the event.


## References

https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/PDF32000_2008.pdf
https://ghostscript.com/~tor/pdfref17.pdf
https://www.adobe.com/content/dam/acom/en/devnet/pdf/adobe_supplement_iso32000.pdf
https://www.pdf-insecurity.org/
https://hxp.io/blog/93/Insomnihack-2022-PDF-Xfiltration/
https://github.com/p4-team/ctf/tree/master/2022-01-29-insomnihack/pdf-xfiltration
