<?php
/*
	Produced 2019-2020
	By https://amattu.com/links/github
	Copy Alec M.
	License GNU Affero General Public License v3.0
*/

/*
	Produced March 6th, 2017
	By https://github.com/shanept/MimeSniffer
	Copy Shanept
	License The Unlicense
*/

class MimeReader {
	// Class Variables
	private $file = null;
	private $detected_type = null;
	private $header = null;
	const IGNORE_NOTHING = '';
	const BINARY_CHARACTERS = "\x00\x01\x02\x03\x04\x05\x06\x07\0x08\x0B\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1C\x1D\x1E\x1F";
	const WHITESPACE_CHARACTERS = "\x09\x0A\x0C\x0D\x20";
	const TAG_TERMINATING_CHARACTERS = "\x20\x3E";
	private static $image = array(
		// Windows Icon
		array(
			'mime'      => 'image/x-icon',
			'pattern'   => "\x00\x00\x01\x00",
			'mask'      => "\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// Windows Cursor signature
		array(
			'mime'      => 'image/x-icon',
			'pattern'   => "\x00\x00\x02\x00",
			'mask'      => "\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "BM" - BMP signature
		array(
			'mime'      => 'image/bmp',
			'pattern'   => "\x42\x4D",
			'mask'      => "\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "GIF87a" - GIF signature
		array(
			'mime'      => 'image/gif',
			'pattern'   => "\x47\x49\x46\x38\x37\x61",
			'mask'      => "\xFF\xFF\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "GIF89a" - GIF signature
		array(
			'mime'      => 'image/gif',
			'pattern'   => "\x47\x49\x46\x38\x39\x61",
			'mask'      => "\xFF\xFF\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "RIFF" followed by 4 bytes followed by "WEBPVP"
		array(
			'mime'      => 'image/webp',
			'pattern'   => "\x52\x49\x46\x46\x00\x00\x00\x00\x57\x45\x42\x50\x56\x50",
			'mask'      => "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// A byte with only the highest bit set followed by the string "PNG" followed by CR LF SUB LF - PNG signature
		array(
			'mime'      => 'image/png',
			'pattern'   => "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
			'mask'      => "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// JPEG start of image marker followed by another marker
		array(
			'mime'      => 'image/jpeg',
			'pattern'   => "\xFF\xD8\xFF",
			'mask'      => "\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "8BPS" - Photoshop signature
		array(
			'mime'      => 'application/psd',
			'pattern'   => "\x38\x42\x50\x53",
			'mask'      => "\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
	);
	private static $media = array(
		// The WebM signature
		array(
			'mime'      => 'video/webm',
			'pattern'   => "\x1A\x45\xDF\xA3",
			'mask'      => "\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// The .snd signature
		array(
			'mime'      => 'audio/basic',
			'pattern'   => "\x2E\x73\x6E\x64",
			'mask'      => "\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "FORM" followed by 4 bytes followed by "AIFF" - the AIFF signature
		array(
			'mime'      => 'audio/aiff',
			'pattern'   => "\x46\x4F\x52\x4D\x00\x00\x00\x00\x41\x49\x46\x46",
			'mask'      => "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// MP3 without ID3 tag
		array(
			'mime'      => 'audio/mpeg',
			'pattern'   => "\xFF\xFB",
			'mask'      => "\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "ID3" and the ID3v2-tagged MP3 signature
		array(
			'mime'      => 'audio/mpeg',
			'pattern'   => "\x49\x44\x33",
			'mask'      => "\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "OggS" followed by NUL - The OGG signature
		array(
			'mime'      => 'application/ogg',
			'pattern'   => "\x4F\x67\x67\x53\x00",
			'mask'      => "\xFF\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "MThd" followed by 4 bytes representing the number 6 in 32 bits (big endian) - MIDI signature
		array(
			'mime'      => 'audio/midi',
			'pattern'   => "\x4D\x54\x68\x64\x00\x00\x00\x06",
			'mask'      => "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "RIFF" followed by 4 bytes followed by "AVI" - AVI signature
		array(
			'mime'      => 'video/avi',
			'pattern'   => "\x52\x49\x46\x46\x00\x00\x00\x00\x41\x56\x49\x20",
			'mask'      => "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "RIFF" followed by 4 bytes followed by "WAVE" - WAVE signature
		array(
			'mime'      => 'audio/wave',
			'pattern'   => "\x52\x49\x46\x46\x00\x00\x00\x00\x57\x41\x56\x45",
			'mask'      => "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
	);
	private static $fonts = array(
		// 34 bytes followed by "LP" - Opentype signature
		array(
			'mime'      => 'application/vnd.ms-fontobject',
			'pattern'   => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4C\x50",
			'mask'      => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// 4 bytes representing version type 1 of true type font
		array(
			'mime'      => 'application/font-ttf',
			'pattern'   => "\x00\x01\x00\x00",
			'mask'      => "\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "OTTO" - Opentype signature
		array(
			'mime'      => 'application/font-off',
			'pattern'   => "\x4F\x54\x54\x4F",
			'mask'      => "\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "ttcf" - Truetype Collection signature
		array(
			'mime'      => 'application/x-font-truetype-collection',
			'pattern'   => "\x74\x74\x63\x66",
			'mask'      => "\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// 'wOFF' - Web Open Font Format signature
		array(
			'mime'      => 'application/font-woff',
			'pattern'   => "\x77\x4F\x46\x46",
			'mask'      => "\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
	);
	private static $archive = array(
		// GZIP signature
		array(
			'mime'      => 'application/x-gzip',
			'pattern'   => "\x1F\x8B\x08",
			'mask'      => "\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "PK" followed by ETX, EOT - ZIP signature
		array(
			'mime'      => 'application/zip',
			'pattern'   => "\x50\x4B\x03\x04",
			'mask'      => "\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "Rar " followed by SUB, BEL, NUL - RAR signature
		array(
			'mime'      => 'application/x-rar-compressed',
			'pattern'   => "\x52\x61\x72\x20\x1A\x07\x00",
			'mask'      => "\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
	);
	private static $text = array(
		// "%!PS-Adobe-" - Postscript signature
		array(
			'mime'      => 'application/postscript',
			'pattern'   => "\x25\x21\x50\x53\x2D\x41\x64\x6F\x62\x65",
			'mask'      => "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// UTF-16 Big Endian BOM text
		array(
			'mime'      => 'text/plain',
			'pattern'   => "\xFF\xFE",
			'mask'      => "\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// UTF-16 Little Endian BOM text
		array(
			'mime'      => 'text/plain',
			'pattern'   => "\xFE\xFF",
			'mask'      => "\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// UTF-8 BOM text
		array(
			'mime'      => 'text/plain',
			'pattern'   => "\xEF\xBB\xBF",
			'mask'      => "\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
	);
	private static $others = array(
		// Windows executable file
		array(
			'mime'      => 'application/x-msdownload',
			'pattern'   => "\x4D\x5A",
			'mask'      => "\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// Unix ELF format - DEL followed by "ELF"
		array(
			'mime'      => 'application/octet-stream',
			'pattern'   => "\x7F\x45\x4C\x46",
			'mask'      => "\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
		// "%PDF" - PDF signature
		array(
			'mime'      => 'application/pdf',
			'pattern'   => "\x25\x50\x44\x46",
			'mask'      => "\xFF\xFF\xFF\xFF",
			'ignore'    => self::IGNORE_NOTHING,
		),
	);
	private static $html = array(
		// "<!DOCTYPE HTML"
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x21\x44\x4F\x43\x54\x59\x50\x45\x20\x48\x54\x4D\x4C",
			'mask'      => "\xFF\xFF\xDF\xDF\xDF\xDF\xDF\xDF\xDF\xFF\xDF\xDF\xDF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<HTML" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x48\x54\x4D\x4C",
			'mask'      => "\xFF\xDF\xDF\xDF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<HEAD" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x48\x45\x41\x44",
			'mask'      => "\xFF\xDF\xDF\xDF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<SCRIPT" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x53\x43\x52\x49\x50\x54",
			'mask'      => "\xFF\xDF\xDF\xDF\xDF\xDF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<IFRAME" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x49\x46\x52\x41\x4D\x45",
			'mask'      => "\xFF\xDF\xDF\xDF\xDF\xDF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<H1" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x48\x31",
			'mask'      => "\xFF\xDF\xFF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<DIV" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x44\x49\x56",
			'mask'      => "\xFF\xDF\xDF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<FONT" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x46\x4F\x4E\x54",
			'mask'      => "\xFF\xDF\xDF\xDF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<TABLE" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x54\x41\x42\x4C\x45",
			'mask'      => "\xFF\xDF\xDF\xDF\xDF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<A" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x41",
			'mask'      => "\xFF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<STYLE" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x53\x54\x59\x4C\x45",
			'mask'      => "\xFF\xDF\xDF\xDF\xDF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<TITLE" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x54\x49\x54\x4C\x45",
			'mask'      => "\xFF\xDF\xDF\xDF\xDF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<B" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x42",
			'mask'      => "\xFF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<BODY" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x42\x4F\x44\x59",
			'mask'      => "\xFF\xDF\xDF\xDF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<BR" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x42\x52",
			'mask'      => "\xFF\xDF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<P"
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x50",
			'mask'      => "\xFF\xDF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// "<!--" followed by a tag-terminating byte
		array(
			'mime'      => 'text/html',
			'pattern'   => "\x3C\x21\x2D\x2D",
			'mask'      => "\xFF\xFF\xFF\xFF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
			'trailing'  => self::TAG_TERMINATING_CHARACTERS,
		),
		// The string "<?xml"
		array(
			'mime'      => 'text/xml',
			'pattern'   => "\x3C\x3F\x78\x6D\x6C",
			'mask'      => "\xFF\xFF\xFF\xFF\xFF",
			'ignore'    => self::WHITESPACE_CHARACTERS,
		),
	);

	/**
	 * Class Constructor
	 *
	 * @param file $handle
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:29:09-040
	 */
	public function __construct($file) {
		$this->file = $file;
	}

	/**
	 * Check if file is empty
	 *
	 * @return boolean empty
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:30:12-040
	 */
	public function isEmpty() : bool {
		return $this->getType() === 'inode/x-empty';
	}

	/**
	 * Check if file is text
	 *
	 * @return boolean text
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:31:05-040
	 */
	public function isText() : bool {
		// Variables
		$detected = false;

		// Checks
		switch ($this->getType()) {
			case 'application/postscript':
			case 'text/plain':
				$detected = true;
				break;
			default:
				break;
		}

		// Return
		return $detected;
	}

	/**
	 * Check if file is fontset
	 *
	 * @return boolean fontset
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:32:02-040
	 */
	public function isFont() : bool {
		// Variables
		$detected = false;

		// Checks
		switch ($this->getType()) {
			case 'application/font-ttf':
			case 'application/font-cff':
			case 'application/font-otf':
			case 'application/font-sntf':
			case 'application/vds.ms-opentype':
			case 'application/font-woff':
			case 'application/vnd.ms-fontobject':
				$detected = true;
				break;
			default:
				break;
		}

		// Return
		return $detected;
	}

	/**
	 * Check if file is a zip archive
	 *
	 * @return boolean zip archive
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:32:38-040
	 */
	public function isZip() : bool {
		// Variables
		$detected = false;

		// Checks
		switch ($this->getType()) {
			case 'application/zip':
				$detected = true;
				break;
			default:
				break;
		}
		if (substr($this->getType(), -4) === '+zip') {
			$detected = true;
		}

		// Return
		return $detected;
	}

	/**
	 * Check if file is a archive
	 *
	 * @return boolean archive
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:33:38-040
	 */
	public function isArchive() : bool {
		// Variables
		$detected = false;

		// Checks
		switch ($this->getType()) {
			case 'application/x-rar-compressed':
			case 'application/zip':
			case 'application/x-gzip':
				$detected = true;
				break;
			default:
				break;
		}

		// Return
		return $detected;
	}

	/**
	 * Check if file is a script
	 *
	 * @return boolean script
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:34:28-040
	 */
	public function isScriptable() : bool {
		// Variables
		$detected = false;

		// Checks
		switch ($this->getType()) {
			case 'text/html':
			case 'application/pdf':
			case 'application/postscript':
				$detected = true;
				break;
			default:
				break;
		}

		// Return
		return $detected;
	}

	/**
	 * Get file type
	 *
	 * @return string mime
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:35:18-040
	 */
	public function getType() : string {
		// Checks
		if (is_null($this->detected_type)) {
			$this->readResourceHeader();
			$this->detectType();
		}

		// Return
		return $this->detected_type;
	}

	/**
	 * Read file magic mime
	 *
	 * @return None
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:36:09-040
	 */
	private function readResourceHeader() : void {
		// Checks
		if (is_string($this->file)) {
			$fp = fopen($this->file, 'r');
			$header = fread($fp, 512);
			fclose($fp);
		} else {
			$position = ftell($this->file);
			fseek($this->file, 0, SEEK_SET);
			$header = fread($this->file, 512);
			fseek($this->file, $position, SEEK_SET);
		}

		// Variables
		$this->header = &$header;
	}

	/**
	 * Determine mime type
	 *
	 * @return None
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:38:27-040
	 */
	private function detectType() : void {
		// Checks
		if ($this->sniffEmpty() || $this->sniffImages() || $this->sniffMedia() || $this->sniffFonts() || $this->sniffArchive() || $this->sniffText() || $this->sniffHtml() || $this->sniffOthers()) {
			return;
		}

		// Variables
		$this->detected_type = 'application/octet-stream';
	}

	/**
	 * Find mime type
	 *
	 * @param string pattern
	 * @param string mask
	 * @param string ignore characters
	 * @return boolean success
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:52:29-040
	 */
	private function matchPattern($pattern, $mask, $ignore) : bool {
		// Checks
		if (empty($pattern) || empty($mask)) {
			return false;
		}

		// Variables
		$s = 0;
		$sequence = &$this->header;
		$seq_len = strlen($sequence);
		$pattern_len = strlen($pattern);
		$mask_len = strlen($mask);

		if ($pattern_len !== $mask_len) {
			return false;
		}

		if (!empty($ignore)) {
			for ($s = 0; $s < $seq_len;) {
				if (strpos($ignore, $sequence[$s]) === false) {
					break;
				}

				++$s;
			}
		}

		if (($seq_len - $s) < $mask_len) {
			return false;
		}

		for ($i = 0; $i < $pattern_len;) {
			$masked_data = $sequence[$s] & $mask[$i];

			if ($masked_data !== $pattern[$i]) {
				return false;
			}

			++$i;
			++$s;
		}

		return true;
	}

	/**
	 * Match mime type against HTML
	 *
	 * @param string pattern
	 * @param string mask
	 * @param string ignore characters
	 * @param string trailing
	 * @return boolean success
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:56:40-040
	 */
	private function htmlMatchPattern($pattern, $mask, $ignore, $trailing) : bool {
		if (empty($pattern) || empty($mask)) {
			return false;
		}

		$s = 0;
		$i = 0;

		$sequence    = &$this->header;
		$seq_len     = strlen($sequence);
		$pattern_len = strlen($pattern);
		$mask_len    = strlen($mask);

		if ($pattern_len !== $mask_len && empty($trailing)) {
			return false;
		}

		if (!empty($ignore)) {
			for (; $s < $seq_len;) {
				if (strpos($ignore, $sequence[$s]) === false) {
					break;
				}

				++$s;
			}
		}

		if (($seq_len - $s) < $mask_len) {
			return false;
		}

		for (; $i < $pattern_len; $i++, $s++) {
			$masked_data = $sequence[$s] & $mask[$i];

			if ($masked_data !== $pattern[$i]) {
				return false;
			}
		}

		for (; $i < $mask_len; $i++, $s++) {
			$masked_data = $sequence[$s] & $mask[$i];

			if (false === strpos($trailing, $masked_data)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Match empty file
	 *
	 * @return boolean empty
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:58:23-040
	 */
	private function sniffEmpty() : bool {
		// Checks
		if (strlen($this->header) === 0) {
			$this->detected_type = 'inode/x-empty';
			return true;
		}

		// Return
		return false;
	}

	/**
	 * Match image files
	 *
	 * @return boolean image
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:58:51-040
	 */
	private function sniffImages() : bool {
		// Variables
		$num_imgs = count(self::$image);

		// Loops
		for ($i = 0; $i < $num_imgs; $i++) {
			$im = &self::$image[$i];
			if ($this->matchPattern($im['pattern'], $im['mask'], $im['ignore'])) {
				$this->detected_type = $im['mime'];
				return true;
			}
		}

		// Return
		return false;
	}

	/**
	 * Match media files
	 *
	 * @return boolean media
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T17:59:56-040
	 */
	private function sniffMedia() : bool {
		$num_media = count(self::$media);

		for ($i = 0; $i < $num_media; $i++) {
			$m = &self::$media[$i];

			if ($this->matchPattern($m['pattern'], $m['mask'], $m['ignore'])) {
				$this->detected_type = $m['mime'];

				return true;
			}
		}

		if ($this->sniffMp4()) {
			$this->detected_type = 'video/mp4';

			return true;
		}

		return false;
	}

	/**
	 * Match against MP4 mimes
	 *
	 * @return boolean success
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T18:07:44-040
	 */
	private function sniffMp4() : bool {
		$sequence = &$this->header;
		$seq_len  = strlen($sequence);

		if ($seq_len < 12) {
			return false;
		}

		$box_size = substr($sequence, 0, 4);
		$box_size = unpack('N', $box_size);
		$box_size = $box_size[1];

		if ($seq_len < $box_size) {
			return false;
		}

		if ($box_size % 4) {
			return false;
		}

		if (substr($sequence, 4, 4) !== "\x66\x74\x79\x70") {
			return false;
		}

		if (substr($sequence, 8, 3) === "\x6D\x70\x34") {
			return true;
		}

		$i = 16;

		while ($i < $box_size) {
			if (substr($sequence, $i, 3) === "\x6D\x70\x34") {
				return true;
			}

			$i += 4;
		}

		return false;
	}

	/**
	 * Match against font mimes
	 *
	 * @return boolean success
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T18:05:27-040
	 */
	private function sniffFonts() : bool {
		$num_fonts = count(self::$fonts);

		for ($i = 0; $i < $num_fonts; $i++) {
			$f = &self::$fonts[$i];

			if ($this->matchPattern($f['pattern'], $f['mask'], $f['ignore'])) {
				$this->detected_type = $f['mime'];

				return true;
			}
		}

		return false;
	}

	/**
	 * Match against archive mimes
	 *
	 * @return boolean success
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T18:05:08-040
	 */
	private function sniffArchive() : bool {
		$num_archives = count(self::$archive);

		for ($i = 0; $i < $num_archives; $i++) {
			$a = &self::$archive[$i];

			if ($this->matchPattern($a['pattern'], $a['mask'], $a['ignore'])) {
				$this->detected_type = $a['mime'];

				return true;
			}
		}

		return false;
	}

	/**
	 * Match against text mimes
	 *
	 * @return boolean succes
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T18:04:42-040
	 */
	private function sniffText() : bool {
		$num_texts = count(self::$text);

		for ($i = 0; $i < $num_texts; $i++) {
			$t = &self::$text[$i];

			if ($this->matchPattern($t['pattern'], $t['mask'], $t['ignore'])) {
				if (!$this->hasBinaryData()) {
					$this->detected_type = $t['mime'];

					return true;
				}

				return false;
			}
		}

		return false;
	}

	/**
	 * Match against HTML mimes
	 *
	 * @return boolean success
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T18:03:54-040
	 */
	private function sniffHtml() : bool {
		$num_html = count(self::$html);

		for ($i = 0; $i < $num_html; $i++) {
			$u = &self::$html[$i];

			if ('text/html' === $u['mime']) {
				$trailing = (array_key_exists('trailing', $u) ? $u['trailing'] : '');

				if ($this->htmlMatchPattern($u['pattern'], $u['mask'], $u['ignore'], $trailing)) {
					$this->detected_type = 'text/html';

					return true;
				}
			} else {
				if ($this->matchPattern($u['pattern'], $u['mask'], $u['ignore'])) {
					$this->detected_type = $u['mime'];

					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Match against miscellaneous mimes
	 *
	 * @return boolean success
	 * @throws
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T18:02:46-040
	 */
	private function sniffOthers() : bool {
		$num_others = count(self::$others);

		for ($i = 0; $i < $num_others; $i++) {
			$o = &self::$others[$i];

			if ($this->matchPattern($o['pattern'], $o['mask'], $o['ignore'])) {
				$this->detected_type = $o['mime'];

				return true;
			}
		}

		return false;
	}

	/**
	 * Match binary file
	 *
	 * @return boolean has binary
	 * @throws None
	 * @author Alec M. <https://amattu.com>
	 * @date 2020-04-14T18:02:13-040
	 */
	private function hasBinaryData() : bool {
		static $binary_chars;

		if (is_string($binary_chars)) {
			$binary_chars = str_split($this->binary_characters);
		}

		$num_chars = count($binary_chars);

		for ($i = 0; $i < $num_chars; $i++) {
			if (strpos($this->header, $binary_chars[$i]) !== false) {
				return true;
			}
		}

		return false;
	}
}
?>
