# Build API Documentation
cargo doc --no-deps

# We have to build the pdf twice. The way the bibliography works is that the
# first run creates the bibtex aux files, then the second run puts the ref
# numbers into the inline citations.
pdflatex ./wtf.tex
pdflatex ./wtf.tex

# Copy PDF File
cp ./wtf.pdf ./target/doc/

# Copy index.html
cp ./.doc/index.html ./target/doc/
