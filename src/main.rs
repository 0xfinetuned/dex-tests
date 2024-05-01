use bitcoincore_rpc::{json::AddressType, Auth, Client, RawTx, RpcApi};
use bitcoin::{
    absolute::LockTime, address::Address, key::{
        Keypair, TapTweak, TweakedKeypair, UntweakedKeypair, XOnlyPublicKey
    }, opcodes::all::OP_RETURN, p2p::address, secp256k1::{
        self, Secp256k1, SecretKey
    }, sighash::{
        Prevouts, SighashCache
    }, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness
};
use borsh::{BorshSerialize, BorshDeserialize};
use rand_core::OsRng;
use std::str::FromStr;
use std::fs;
use anyhow::{Result, anyhow};
use sha256::digest;
use serde::{Serialize, Deserialize};
use serde_json::{Value, from_str, to_string, json};
use std::cell::RefCell;
use std::{thread, time};
use ordinals::{Edict, Etching, Rune, RuneId, Runestone, Terms};
use runes::rune_id;

fn get_trader(trader_id: u64) -> (Keypair, XOnlyPublicKey, Address) {
    let secp = Secp256k1::new();

    let secret_key = match fs::read_to_string(&format!(".arch/trader{}.json", trader_id)) {
        Ok(data) => {
            SecretKey::from_str(&data).unwrap()
        },
        Err(_) => {
            let (sec_key, _) = secp.generate_keypair(&mut OsRng);
            fs::write(&format!(".arch/trader{}.json", trader_id), &sec_key.display_secret().to_string()).expect("Unable to write file");
            sec_key
        }
    };

    let keypair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
    let (publickey, _parity) = XOnlyPublicKey::from_keypair(&keypair);

    let address = Address::p2tr(&secp, publickey, None, bitcoin::Network::Regtest);

    (keypair, publickey, address)
}

fn send_premine_tx() -> Txid {
    let rpc = Client::new("https://bitcoin-node.dev.aws.archnetwork.xyz:18443/wallet/testwallet",
                Auth::UserPass("bitcoin".to_string(),
                                "428bae8f3c94f8c39c50757fc89c39bc7e6ebc70ebf8f618".to_string())).unwrap();

    let secp = Secp256k1::new();

    let secret_key = match fs::read_to_string(&format!(".arch/trader{}.json", 0)) {
        Ok(data) => {
            SecretKey::from_str(&data).unwrap()
        },
        Err(_) => {
            let (sec_key, _) = secp.generate_keypair(&mut OsRng);
            fs::write(&format!(".arch/trader{}.json", 0), &sec_key.display_secret().to_string()).expect("Unable to write file");
            sec_key
        }
    };

    let keypair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
    let (publickey, _parity) = XOnlyPublicKey::from_keypair(&keypair);

    let address = Address::p2tr(&secp, publickey, None, bitcoin::Network::Regtest);

    let txid = rpc.send_to_address(
        &address, Amount::from_sat(10000), None, None, None, None, None, None
    ).unwrap();

    let runestone = Runestone {
        edicts: vec![],
        etching: Some(Etching {
            divisibility: Some(1),
            premine: Some(1_000_000),
            rune: Some(Rune(101)),
            spacers: None,
            symbol: Some('E'),
            terms: None
        }),
        mint: None,
        pointer: None
    };
    println!("{:?}", runestone.encipher());

    let mut premine_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new()
            }
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(runestone.encipher().to_bytes())
            },
            TxOut {
                value: Amount::from_sat(9500),
                script_pubkey: address.script_pubkey()
            }
        ]
    };

    let sighash_type = TapSighashType::Default;
    let prevouts = vec![
        rpc.get_raw_transaction(&txid, None).unwrap().output[0].clone()
    ];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&mut premine_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
    let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, None);
    let msg = secp256k1::Message::from(sighash);
    let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    // Update the witness stack.
    let signature = bitcoin::taproot::Signature { sig: signature, hash_ty: sighash_type };
    premine_tx.input[0].witness.push(signature.to_vec());

    // BOOM! Transaction signed and ready to broadcast.
    rpc.send_raw_transaction(premine_tx.raw_hex()).unwrap()
}

fn airdrop_runes(txid: Txid) -> Txid {
    let rpc = Client::new("https://bitcoin-node.dev.aws.archnetwork.xyz:18443/wallet/testwallet",
                Auth::UserPass("bitcoin".to_string(),
                                "428bae8f3c94f8c39c50757fc89c39bc7e6ebc70ebf8f618".to_string())).unwrap();

    let secp = Secp256k1::new();

    let secret_key = match fs::read_to_string(&format!(".arch/trader{}.json", 0)) {
        Ok(data) => {
            SecretKey::from_str(&data).unwrap()
        },
        Err(_) => {
            let (sec_key, _) = secp.generate_keypair(&mut OsRng);
            fs::write(&format!(".arch/trader{}.json", 0), &sec_key.display_secret().to_string()).expect("Unable to write file");
            sec_key
        }
    };

    let keypair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
    let (publickey, _parity) = XOnlyPublicKey::from_keypair(&keypair);

    let address = Address::p2tr(&secp, publickey, None, bitcoin::Network::Regtest);

    let runestone = Runestone {
        edicts: (0..10).map(|trader_id| {
            Edict {
                id: RuneId { block: 14129, tx: 2 },
                amount: 10,
                output: trader_id+1
            }
        }).collect::<Vec<Edict>>(),
        etching: None,
        mint: None,
        pointer: None
    };

    let mut output = (0..10).map(|trader_id| {
        let (keypair, publickey, address) = get_trader(trader_id);
        TxOut {
            value: Amount::from_sat(500),
            script_pubkey: address.script_pubkey()
        }
    }).collect::<Vec<TxOut>>();
    output.insert(0, TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::from_bytes(runestone.encipher().to_bytes()) });

    let mut airdrop_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid, vout: 1 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new()
            }
        ],
        output
    };

    let sighash_type = TapSighashType::Default;
    let prevouts = vec![
        rpc.get_raw_transaction(&txid, None).unwrap().output[1].clone()
    ];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&mut airdrop_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
    let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, None);
    let msg = secp256k1::Message::from(sighash);
    let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    // Update the witness stack.
    let signature = bitcoin::taproot::Signature { sig: signature, hash_ty: sighash_type };
    airdrop_tx.input[0].witness.push(signature.to_vec());

    // BOOM! Transaction signed and ready to broadcast.
    rpc.send_raw_transaction(airdrop_tx.raw_hex()).unwrap()
}

#[derive(Serialize, Deserialize, Debug, BorshSerialize, BorshDeserialize, Default)]
pub struct OpenPoolParams {
    pub creator: String,
    pub fee_address: String,
    pub liq_ratio: u64,
    pub rune_id: rune_id::RuneId,
    pub fee_txid: String,
    pub fee_vout: u32,
    pub buy_fee: Option<u64>,
    pub sell_fee: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, BorshSerialize, BorshDeserialize)]
enum Method {
    OpenPool,
    AddLiquidity,
    RemoveLiquidity,
    SwapBtcForRunes,
    SwapRunesForBtc,
    // ClaimFees,
    // UpdateFees,
}

#[derive(Serialize, Deserialize, Debug, BorshSerialize, BorshDeserialize)]
struct DexInstruction {
    method: Method,
    data: Vec<u8>,
}

fn open_pool_test(program_id: Pubkey, fee_txid: String, fee_vout: u32) -> Txid {
    let secp = Secp256k1::new();
    let secret_key = match fs::read_to_string(".arch/trader0.json") {
        Ok(data) => {
            SecretKey::from_str(&data).unwrap()
        },
        Err(_) => {
            let (sec_key, _) = secp.generate_keypair(&mut OsRng);
            fs::write(".arch/trader0.json", &sec_key.display_secret().to_string()).expect("Unable to write file");
            sec_key
        }
    };

    let key_pair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let data = borsh::to_vec(&OpenPoolParams {
        creator: "".to_string(),
        fee_address: "".to_string(),
        liq_ratio: 0,
        rune_id: rune_id::RuneId {
            block: 1,
            tx: 4
        },
        fee_txid,
        fee_vout,
        buy_fee: None,
        sell_fee: None,
    }).unwrap();

    let mut instruction_data = vec![0];
    instruction_data.extend(borsh::to_vec(&DexInstruction {
        method: Method::OpenPool,
        data
    }).unwrap());

    let instruction = Instruction {
        program_id,
        utxos: vec![
            UtxoMeta {
                txid,
                vout
            }
        ],
        data: instruction_data
    };

    let message = Message {
        signers: vec![Pubkey(public_key.serialize().to_vec())],
        instructions: vec![instruction]
    };

    let digest_slice = hex::decode(message.hash().unwrap()).unwrap();

    let sig_message = secp256k1::Message::from_digest_slice(&digest_slice).unwrap();

    let sig = secp.sign_schnorr(&sig_message, &key_pair);

    let params = RuntimeTransaction {
        version: 0,
        signatures: vec![
            Signature(sig.serialize().to_vec())
        ],
        message
    };

    let client = reqwest::blocking::Client::new();
    let res = client.post("http://127.0.0.1:9001/")
        .header("content-type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0", 
            "id": "curlycurl", 
            "method": "send_transaction",
            "params": params
        }))
        .send()
        .unwrap();

    let result = from_str::<Value>(&res.text().unwrap()).unwrap();

    println!("send transaction test {:?}", result);
    result["result"].as_str().unwrap().to_string()
}

fn main() {

    let rpc = Client::new("https://bitcoin-node.dev.aws.archnetwork.xyz:18443/wallet/testwallet",
                Auth::UserPass("bitcoin".to_string(),
                                "428bae8f3c94f8c39c50757fc89c39bc7e6ebc70ebf8f618".to_string())).unwrap();

    let airdropped_rune_tx = airdrop_runes(send_premine_tx());
    let deployed_program_id = Pubkey(hex::decode(deploy_program_test()).unwrap());

    let state_txid = send_utxo();

    assign_authority_test(
        Utxo { txid: state_txid.clone(), vout: 1, value: 1500 }, 
        deployed_program_id.clone(),
        vec![]
    );

    read_utxo(format!("{}:1", state_txid.clone()));
    
/*
    let (trader0_keypair, trader0_public_key) = get_trader(0);
    rpc.generate_to_address(block_num, address)

    for trader_id in 1..10 {
        // loads/generates keys for traders
        let (trader_keypair, trader_public_key) = get_trader(trader_id);


    }

    let key_pair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let deployed_program_id = Pubkey(hex::decode(deploy_program_test()).unwrap());

    let state_txid = send_utxo();
    let fee_txid = send_utxo();

    assign_authority_test(
        Utxo { txid: state_txid.clone(), vout: 1, value: 1500 }, 
        deployed_program_id.clone(),
        vec![]
    );

    assign_authority_test(
        Utxo { txid: fee_txid.clone(), vout: 1, value: 1500 }, 
        Pubkey(public_key.serialize().to_vec()),
        vec![]
    );

    read_utxo(format!("{}:1", state_txid.clone()));
    read_utxo(format!("{}:1", fee_txid.clone()));

    let txid = send_transaction_test(
        deployed_program_id, 
        state_txid.clone(),
        1,
        fee_txid
    );

    let ten_millis = time::Duration::from_secs(60);
    thread::sleep(ten_millis);

    get_best_block();
    get_processed_transaction(txid);
*/
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, BorshSerialize)]
pub struct InitBridgeParams {
    pub fee_txid: String,
    pub fee_vout: u32
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct BridgeParams {
    pub instruction_name: String,
    pub instruction_params: String
}

fn send_transaction_test(program_id: Pubkey, txid: String, vout: u32, fee_txid: String) -> String {

    let secp = Secp256k1::new();
    let secret_key = match fs::read_to_string(".arch/trader0.json") {
        Ok(data) => {
            SecretKey::from_str(&data).unwrap()
        },
        Err(_) => {
            let (sec_key, _) = secp.generate_keypair(&mut OsRng);
            fs::write(".arch/trader0.json", &sec_key.display_secret().to_string()).expect("Unable to write file");
            sec_key
        }
    };

    let key_pair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let mut data = vec![0];
    data.extend(borsh::to_vec(&InitBridgeParams {
        fee_txid,
        fee_vout: 1
    }).unwrap());

    let instruction = Instruction {
        program_id,
        utxos: vec![
            UtxoMeta {
                txid,
                vout
            }
        ],
        data
    };

    let message = Message {
        signers: vec![Pubkey(public_key.serialize().to_vec())],
        instructions: vec![instruction]
    };

    let digest_slice = hex::decode(message.hash().unwrap()).unwrap();

    let sig_message = secp256k1::Message::from_digest_slice(&digest_slice).unwrap();

    let sig = secp.sign_schnorr(&sig_message, &key_pair);

    let params = RuntimeTransaction {
        version: 0,
        signatures: vec![
            Signature(sig.serialize().to_vec())
        ],
        message
    };

    let client = reqwest::blocking::Client::new();
    let res = client.post("http://127.0.0.1:9001/")
        .header("content-type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0", 
            "id": "curlycurl", 
            "method": "send_transaction",
            "params": params
        }))
        .send()
        .unwrap();

    let result = from_str::<Value>(&res.text().unwrap()).unwrap();

    println!("send transaction test {:?}", result);
    result["result"].as_str().unwrap().to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeployProgramParams {
    elf: Vec<u8>
}

fn deploy_program_test() -> String {

    let elf = fs::read("program_elf").unwrap();

    let params = DeployProgramParams {
        elf
    };

    let client = reqwest::blocking::Client::new();
    let res = client.post("http://127.0.0.1:9001/")
        .header("content-type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0", 
            "id": "curlycurl", 
            "method": "deploy_program",
            "params": params
        }))
        .send()
        .unwrap();
    
    let result = from_str::<Value>(&res.text().unwrap()).unwrap();
    println!("{:?}", result);
    
    result["result"].as_str().unwrap().to_string()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReadUtxoParams {
    utxo_id: String,
}

fn read_utxo(utxo_id: String) {

    let params = ReadUtxoParams {
        utxo_id
    };

    let client = reqwest::blocking::Client::new();
    let res = client.post("http://127.0.0.1:9001/")
        .header("content-type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0", 
            "id": "curlycurl", 
            "method": "read_utxo",
            "params": params
        }))
        .send()
        .unwrap();

    let result = res.text().unwrap();

    println!("{:?}", result);

    println!("read utxo {:?}", from_str::<Value>(from_str::<Value>(&result).unwrap()["result"].as_str().unwrap()).unwrap());

}

fn get_best_block() {

    let client = reqwest::blocking::Client::new();
    let res = client.post("http://127.0.0.1:9001/")
        .header("content-type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0", 
            "id": "curlycurl", 
            "method": "get_best_block_hash"
        }))
        .send();

    let result = res.unwrap().text().unwrap();

    println!("{:?}", result);
    

    let binding = &from_str::<Value>(&result).unwrap()["result"];
    let best_block_hash = binding.as_str().unwrap();
    

    let res = client.post("http://127.0.0.1:9001/")
        .header("content-type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0", 
            "id": "curlycurl", 
            "method": "get_block",
            "params": best_block_hash
        }))
        .send();

    println!("{:?}", res);

    let result = res.unwrap().text().unwrap();

    println!("{:?}", result);

}

fn get_processed_transaction(txid: String) {

    let client = reqwest::blocking::Client::new();
    let res = client.post("http://127.0.0.1:9001/")
        .header("content-type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0", 
            "id": "curlycurl", 
            "method": "get_processed_transaction",
            "params": txid
        }))
        .send()
        .unwrap();

    let result = res.text().unwrap();

    println!("{:?}", result);

}

fn send_utxo() -> String {

    let rpc = Client::new("https://bitcoin-node.dev.aws.archnetwork.xyz:18443/wallet/testwallet",
                Auth::UserPass("bitcoin".to_string(),
                                "428bae8f3c94f8c39c50757fc89c39bc7e6ebc70ebf8f618".to_string())).unwrap();

    let secp = Secp256k1::new();
    let secret_key = match fs::read_to_string(".arch/trader0.json") {
        Ok(data) => {
            SecretKey::from_str(&data).unwrap()
        },
        Err(_) => {
            let (sec_key, _) = secp.generate_keypair(&mut OsRng);
            fs::write(".arch/trader0.json", &sec_key.display_secret().to_string()).expect("Unable to write file");
            sec_key
        }
    };

    let key_pair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let address = Address::p2tr(&secp, public_key, None, bitcoin::Network::Regtest);

    println!("{:?}", address);

    let txid = rpc.send_to_address(&address, Amount::from_sat(3000), None, None, None, None, None, None).unwrap();

    let network_address = get_network_address("");

    println!("{:#?}", network_address);

    let mut tx = Transaction {
        version: Version::TWO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid,
                    vout: 0
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new()
            }
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::builder().push_opcode(OP_RETURN).push_x_only_key(&public_key).into_script()
            },
            TxOut {
                value: Amount::from_sat(1500),
                script_pubkey: Address::from_str(&network_address).unwrap().require_network(bitcoin::Network::Regtest).unwrap().script_pubkey()
            }
        ],
        lock_time: LockTime::ZERO
    };

    let sighash_type = TapSighashType::Default;
    let prevouts = vec![
        rpc.get_raw_transaction(&txid, None).unwrap().output[0].clone()
    ];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&mut tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
    let tweaked: TweakedKeypair = key_pair.tap_tweak(&secp, None);
    let msg = secp256k1::Message::from(sighash);
    let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    // Update the witness stack.
    let signature = bitcoin::taproot::Signature { sig: signature, hash_ty: sighash_type };
    tx.input[0].witness.push(signature.to_vec());

    // BOOM! Transaction signed and ready to broadcast.
    rpc.send_raw_transaction(tx.raw_hex()).unwrap().to_string()
    
}

fn assign_authority_test(utxo: Utxo, authority: Pubkey, data: Vec<u8>) {

    let secp = Secp256k1::new();
    let secret_key = match fs::read_to_string(".arch/trader0.json") {
        Ok(data) => {
            SecretKey::from_str(&data).unwrap()
        },
        Err(_) => {
            let (sec_key, _) = secp.generate_keypair(&mut OsRng);
            fs::write(".arch/trader0.json", &sec_key.display_secret().to_string()).expect("Unable to write file");
            sec_key
        }
    };

    let key_pair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
    
    let message = AuthorityMessage {
        utxo,
        data,
        authority
    };

    let msg_hash = message.hash().unwrap();

    let hex_digest = hex::decode(msg_hash).unwrap();

    let sig_message = secp256k1::Message::from_digest_slice(&hex_digest).unwrap();

    let sig = secp.sign_schnorr(&sig_message, &key_pair);

    let params = AssignAuthorityParams {
        signature: Signature(sig.serialize().to_vec()),
        message
    };

    let client = reqwest::blocking::Client::new();
    let res = client.post("http://127.0.0.1:9001/")
        .header("content-type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0", 
            "id": "curlycurl", 
            "method": "assign_authority",
            "params": params
        }))
        .send()
        .unwrap();

    let result = res.text().unwrap();

    println!("{:?}", from_str::<Value>(&result).unwrap());
    
}

fn get_network_address(data: &str) -> String {

    let client = reqwest::blocking::Client::new();
    let res = client.post("http://127.0.0.1:9001/")
        .header("content-type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0", 
            "id": "curlycurl", 
            "method": "get_contract_address",
            "params": {
                "data": data.as_bytes()
            }
        }))
        .send()
        .unwrap();

    let result = res.text().unwrap();

    println!("{:?}", result);

    from_str::<Value>(&result).unwrap()["result"].as_str().unwrap().to_string()

}

fn get_address_utxos(rpc: &Client, address: String) -> Vec<Value> {
    let client = reqwest::blocking::Client::new();

    let res = client
        .get(format!("https://mempool.dev.aws.archnetwork.xyz/api/address/{}/utxo", address))
        .header("Accept", "application/json")
        .send()
        .unwrap();

    let utxos = from_str::<Value>(&res.text().unwrap()).unwrap();

    utxos.as_array()
        .unwrap()
        .iter()
        .filter(|utxo| utxo["status"]["block_height"].as_u64().unwrap() <= rpc.get_block_count().unwrap() - 100)
        .map(|utxo| utxo.clone())
        .collect()
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthorityMessage {
    utxo: Utxo,
    data: Vec<u8>,
    authority: Pubkey,
}

impl AuthorityMessage {
    pub fn hash(&self) -> Result<String> {
        Ok(digest(digest(match to_string(self) {
            Ok(d) => d,
            Err(err) => return Err(anyhow!(err)),
        })))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssignAuthorityParams {
    signature: Signature,
    message: AuthorityMessage,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct RuntimeTransaction {
    pub version: u32,
    pub signatures: Vec<Signature>,
    pub message: Message,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Signature(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Message {
    pub signers: Vec<Pubkey>,
    pub instructions: Vec<Instruction>,
}

impl Message {
    pub fn hash(&self) -> Result<String> {
        Ok(digest(digest(match borsh::to_vec(self) {
            Ok(d) => d,
            Err(err) => return Err(anyhow!(err)),
        })))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Pubkey(pub Vec<u8>);

impl Pubkey {
    pub fn to_string(&self) -> Result<String> {
        Ok(String::from_utf8(self.0.clone())?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct UtxoMeta {
    pub txid: String,
    pub vout: u32,
}

impl UtxoMeta {
    pub fn id(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub authority: RefCell<Pubkey>,
    pub data: RefCell<Vec<u8>>,
}

impl UtxoInfo {
    pub fn id(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub utxos: Vec<UtxoMeta>,
    pub data: Vec<u8>,
}

impl RuntimeTransaction {
    pub fn txid(&self) -> Result<String> {
        Ok(digest(digest(borsh::to_vec(self)?)))
    }
}