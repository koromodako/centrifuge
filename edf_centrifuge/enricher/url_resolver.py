"""URL resolver enricher"""

from dataclasses import dataclass, field

from ..atom import URL
from ..helper.aiohttp import CTX_EXT_SESSION, aiohttp_cleanup_ctx_impl
from ..helper.logging import get_logger
from ..record import Record
from .base import (
    Enricher,
    EnricherConfig,
    EnricherContext,
    Feedback,
    register_enricher,
)

GUID = 'url_resolver'
# Based on https://github.com/MISP/misp-warninglists/blob/main/lists/url-shortener/list.json e35df33c
DEFAULT_KNOWN_SHORTENERS = {
    '1url.com',
    '73.nu',
    'bit.ly',
    'bl.ink',
    'cutt.ly',
    'd.to',
    'foxly.me',
    'gg.gg',
    'is.gd',
    'kurzelinks.de',
    'kutt.it',
    'lstu.fr',
    'lyn.bz',
    'oe.cd',
    'ow.ly',
    'rbnd.ly',
    'reduced.to',
    'rip.to',
    'san.aq',
    'shorturl.at',
    'spoo.me',
    'switchy.io',
    't.ly',
    't2m.co',
    'tinu.be',
    'tiny.cc',
    'to.short.cm',
    'urlr.me',
    'urlsz.com',
    'v.gd',
    'www.shorturl.at',
    'yaso.su',
    '2h.ae',
    '2ly.link',
    '2no.co',
    '2uuu.me',
    '3c5.com',
    '42url.com',
    '4x.si',
    '7x.qa',
    '9lick.me',
    'abre.ai',
    'adcraft.co',
    'adcrun.ch',
    'adf.ly',
    'adflav.com',
    'aiy.ooo',
    'aka.gr',
    'amzn.to',
    'artist.link',
    'b2n.ir',
    'bc.vc',
    'bee4.biz',
    'belea.link',
    'bit.do',
    'bit.ly',
    'bitly.com.vn',
    'bitly.com',
    'bitly.lc',
    'bitly.ws',
    'bom.so',
    'buff.ly',
    'buzurl.com',
    'bx.ms',
    'cektkp.com',
    'ci.ci',
    'clc.li',
    'clck.ru',
    'cml.lol',
    'coki.me',
    'cur.lv',
    'cut.by',
    'cutt.ly',
    'cutt.us',
    'cuty.io',
    'd.to',
    'db.tt',
    'dft.ba',
    'dik.si',
    'dub.co',
    'dub.sh',
    'dwz.mk',
    'e.vg',
    'encr.pw',
    'encurtador.dev',
    'etd.bz',
    'filoops.info',
    'flowto.it',
    'fun.ly',
    'fzy.co',
    'gg-l.xyz',
    'go.ly',
    'gog.li',
    'golinks.co',
    'goo.by',
    'goo.gd',
    'goo.gl',
    'goo.su',
    'han.gl',
    'hit.my',
    'hyp.ae',
    'hyperurl.co',
    'i3l.ir',
    'ic9.in',
    'id.tl',
    'idm.in',
    'iii.im',
    'iiil.io',
    'ilang.in',
    'inlnk.co',
    'insprl.com',
    'iplogger.com',
    'iplogger.org',
    'is.gd',
    'ito.mx',
    'ity.im',
    'iurl.vip',
    'j.mp',
    'jii.li',
    'komin.fo',
    'kortlink.dk',
    'kutti.co',
    'l.ead.me',
    'lc.cx',
    'link.zip.net',
    'linksshortcut.com',
    'linkto.im',
    'litby.us',
    'ln.run',
    'lnk.co',
    'lnk.direct',
    'lnk.ink',
    'lnk.pw',
    'lnkd.in',
    'lnkfi.re',
    'long.af',
    'longurl.in',
    'maxiurl.com',
    'mcaf.ee',
    'me2.do',
    'merky.de',
    'mjt.lu',
    'mtr.bio',
    'my5353.com',
    'mylinks.ai',
    'myqrcode.mobi',
    'n9.cl',
    'nanourly.in',
    'neya.io',
    'nov.io',
    'o2o.to',
    'odesli.co',
    'onelink.to',
    'onx.la',
    'ouvaton.link',
    'ow.ly',
    'p6l.org',
    'picz.us',
    'po.st',
    'postly.link',
    'ppt.cc',
    'prettylinkpro.com',
    'q-r.to',
    'q.gs',
    'qr-codes.io',
    'qr.ae',
    'qr.net',
    'qrco.de',
    'qrcodes.pro',
    'qrkit.co',
    'rb.gy',
    'rebrand.ly',
    'rebrandly.com',
    'rebrandly.info',
    'relink.is',
    'reurl.cc',
    'ricardo.news',
    's.devh.in',
    's.ee',
    's.id',
    's.rlp.de',
    's3r.io',
    's59.site',
    'scrnch.me',
    'shly.link',
    'shorten.ee',
    'shorten.is',
    'shorten.tv',
    'shorter.me',
    'shortquik.com',
    'shorturl.ae',
    'shorturl.asia',
    'shorturl.at',
    'shrtcnl.com',
    'sht.ac',
    'sk.gy',
    'sl8.in',
    'smarturl.it',
    'smurl.fr',
    'sn.rs',
    'snip.ly',
    'song.link',
    'spoo.me',
    'sprl.in',
    'srink.co',
    'su.pr',
    'surl.li',
    't.co',
    't.ly',
    'temporary-url.com',
    'tg.pe',
    'tiny.cc',
    'tinyarrows.com',
    'tinyurl.com',
    'tinyurl.mobi',
    'tota2.com',
    'tr.ee',
    'tr.im',
    'trimz.me',
    'tt.vg',
    'tweez.me',
    'twitthis.com',
    'twixar.com',
    'twixar.me',
    'tyny.to',
    'u.bb',
    'u.to',
    'urled.cc',
    'urled.pro',
    'urless.com',
    'urlr.me',
    'urlshort.dev',
    'urltin.com',
    'urlz.fr',
    'ux9.de',
    'v.gd',
    'v.ht',
    'vtaurl.com',
    'vzturl.com',
    'webz.cc',
    'wp.me',
    'x.co',
    'xlinkz.info',
    'xtu.me',
    'xy2.eu',
    'yirra.net',
    'ykm.de',
    'yourls.org',
    'youtu.be',
    'yu2.it',
    'yu3.io',
    'zpag.es',
    'zpr.io',
    'zurl.to',
    'zws.im',
    'zzb.bz',
    'sor.bz',
}
_LOGGER = get_logger('enricher.')


@dataclass(kw_only=True)
class URLResolverEngineConfig(EnricherConfig):
    """URL resolver enricher config"""

    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    max_depth: int = 5
    known_shorteners: set[str] = field(default_factory=set)

    @property
    def valid(self) -> bool:
        return bool(self.known_shorteners)

    @classmethod
    def from_dict(cls, dct):
        instance = super().from_dict(dct)
        instance.proxy = dct.get('proxy')
        instance.headers = dct.get('headers', {})
        instance.max_depth = int(dct.get('max_depth', 5))
        instance.known_shorteners = set(
            dct.get('known_shorteners', DEFAULT_KNOWN_SHORTENERS)
            or DEFAULT_KNOWN_SHORTENERS
        )
        return instance


async def _unshorten(ctx: EnricherContext, url: str) -> str | None:
    session = ctx.ext[CTX_EXT_SESSION]
    async with session.get(url.parsed, allow_redirects=False) as resp:
        if resp.status not in {301, 302, 307, 308}:
            _LOGGER.info("unexpected status: %s", resp.status)
            return None
        return resp.headers.get('Location')


def _match_unshortener(ctx: EnricherContext, url: URL) -> bool:
    return url.parsed.host in ctx.config.known_shorteners


async def _enrich_url_impl(
    ctx: EnricherContext, url: URL, _feedback: Feedback
) -> Record:
    if not _match_unshortener(ctx, url):
        return {'expanded': None}
    location = url
    remaining = ctx.config.max_depth
    while remaining > 0:
        remaining -= 1
        _LOGGER.info("unshortening(%d): %s", remaining, location.value)
        location = await _unshorten(ctx, location)
        if not location:
            return {'expanded': None}
        location = URL.parse(location, psl_index=ctx.psl_index)
        if not _match_unshortener(ctx, location):
            _LOGGER.info("found(%d): %s", remaining, location.value)
            return {'expanded': location.value}
    return {'expanded': None}


_FIELDS = ('expanded',)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        URL: _enrich_url_impl,
    },
    cleanup_ctx_impl=aiohttp_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, URLResolverEngineConfig)
