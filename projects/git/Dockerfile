FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        cvs cvsps gettext libcgi-pm-perl libcurl4-gnutls-dev \
        libdbd-sqlite3-perl liberror-perl libexpat1-dev libhttp-date-perl \
        libio-pty-perl libmailtools-perl libpcre2-dev libpcre3-dev libsvn-perl \
        perl-modules libyaml-perl libz-dev python subversion tcl unzip \
        asciidoc docbook-xsl xmlto libssl-dev zip
RUN git clone --depth 1 https://github.com/git/git git
RUN git clone --depth 1 https://github.com/madler/zlib
WORKDIR $SRC/git
COPY build.sh $SRC/
COPY harnesses/*.c $SRC/harnesses/
COPY seeds/*_seed_corpus.zip $SRC/harnesses/
# This is to fix Fuzz Introspector build by using LLVM old pass manager
# re https://github.com/ossf/fuzz-introspector/issues/305
ENV OLD_LLVMPASS=1
