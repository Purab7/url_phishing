"""Apply the supplied DSATM cover image, then retain generated report pages."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from pypdf import PdfReader, PdfWriter

ROOT=Path(__file__).resolve().parent
TEMPLATE=ROOT/'cover_template_300dpi.png'
REPORT=ROOT/'Mini_Project_Report.pdf'
image=Image.open(TEMPLATE).convert('RGB')
scale=image.width/992.0
font_dir=Path(r'C:\Windows\Fonts')
normal=ImageFont.truetype(str(font_dir/'times.ttf'),round(16*scale))
bold=ImageFont.truetype(str(font_dir/'timesbd.ttf'),round(16*scale))

def cover_box(box):
    ImageDraw.Draw(image).rectangle(tuple(round(v*scale) for v in box),fill='white')

cover_box((115,390,880,440))
draw=ImageDraw.Draw(image)
draw.text((496*scale,425*scale),'Agentic AI-Based Phishing URL Detection and Analysis System',
          font=bold,fill='black',anchor='mm')
students=[('1DT23CY016','DAKSH'),('1DT23CY009','APURUPA'),
          ('1DT23CY010','ASHA'),('1DT23CY035','PURAB')]
rows=[(529,564),(564,598),(598,632),(632,666)]
for (usn,name),(top,bottom) in zip(students,rows):
    cover_box((367,top+2,624,bottom-2))
    cover_box((626,top+2,883,bottom-2))
    draw=ImageDraw.Draw(image)
    y=((top+bottom)/2)*scale
    draw.text((381*scale,y),usn,font=normal,fill='black',anchor='lm')
    draw.text((635*scale,y),name,font=normal,fill='black',anchor='lm')
cover_box((105,695,700,730))
draw=ImageDraw.Draw(image)
draw.text((108*scale,712*scale),'Subject: Vulnerability Assessment and Penetration Testing',
          font=normal,fill='black',anchor='lm')
cover_box((105,765,510,858))
draw=ImageDraw.Draw(image)
draw.text((108*scale,780*scale),'Faculty Guide:',font=normal,fill='black',anchor='lm')
draw.text((108*scale,805*scale),'Shivam Goswami',font=normal,fill='black',anchor='lm')

cover_pdf=ROOT/'cover_flat.pdf'
c=canvas.Canvas(str(cover_pdf),pagesize=A4)
c.drawImage(ImageReader(image),0,0,width=A4[0],height=A4[1],preserveAspectRatio=False,mask='auto')
c.save()
cover=PdfReader(str(cover_pdf))
body=PdfReader(str(REPORT))
writer=PdfWriter()
writer.add_page(cover.pages[0])
for page in body.pages[1:]:
    writer.add_page(page)
writer.add_metadata({'/Title':'Agentic AI-Based Phishing URL Detection and Analysis System',
                     '/Subject':'Vulnerability Assessment and Penetration Testing'})
temp=ROOT/'Mini_Project_Report.final.pdf'
with temp.open('wb') as stream:
    writer.write(stream)
temp.replace(REPORT)
cover_pdf.unlink(missing_ok=True)
print(REPORT)
