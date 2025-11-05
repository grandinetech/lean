use libp2p::gossipsub::{DataTransform, Message, RawMessage, TopicHash};
use snap::raw::{Decoder, Encoder};

pub struct Compressor;

impl Compressor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new()
    }
}
impl DataTransform for Compressor {
    fn inbound_transform(&self, raw_message: RawMessage) -> Result<Message, std::io::Error> {
        let mut decoder = Decoder::new();
        let data = decoder.decompress_vec(&raw_message.data)?;

        Ok(Message {
            topic: raw_message.topic,
            data,
            sequence_number: raw_message.sequence_number,
            source: raw_message.source,
        })
    }

    fn outbound_transform(
        &self,
        _topic: &TopicHash,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut encoder = Encoder::new();
        let raw_message = encoder.compress_vec(&data)?;

        Ok(raw_message)
    }
}
