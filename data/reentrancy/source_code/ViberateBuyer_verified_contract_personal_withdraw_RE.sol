/*
 * ===== SmartInject Injection Details =====
 * Function      : personal_withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a multi-transaction reentrancy vulnerability by reordering the token transfer external calls to occur BEFORE state updates (balances[msg.sender] = 0 and contract_eth_value update). This creates a window where an attacker can exploit the contract through multiple transactions:
 * 
 * 1. TRANSACTION 1: Attacker calls personal_withdraw() with a malicious ERC20 token contract
 * 2. During the token.transfer() call, the malicious token contract calls back into personal_withdraw()
 * 3. Since balances[msg.sender] hasn't been zeroed yet, the attacker can withdraw again
 * 4. TRANSACTION 2+: The attacker can repeat this process multiple times before the original transaction completes
 * 
 * The vulnerability requires:
 * - Multiple transactions to set up the malicious token contract
 * - State persistence between calls (balances[msg.sender] remains non-zero during reentrancy)
 * - Accumulated effect across multiple withdrawals that drain more tokens than the user is entitled to
 * 
 * This is a realistic vulnerability pattern where external calls are made before state updates, creating a classic reentrancy attack vector that requires careful transaction sequencing to exploit.
 */
pragma solidity ^0.4.13;

// Viberate ICO buyer
// Avtor: Janez

// ERC20 Interface: https://github.com/ethereum/EIPs/issues/20
contract ERC20 {
  function transfer(address _to, uint256 _value) returns (bool success);
  function balanceOf(address _owner) constant returns (uint256 balance);
}

contract ViberateBuyer {
  // Koliko ETH je vlozil vsak racun.
  mapping (address => uint256) public balances;
  // Nagrada za izvedbo nakupa.
  uint256 public buy_bounty;
  // Nagrada za dvig.
  uint256 public withdraw_bounty;
  // Podatek ali smo tokene uspesno kupili.
  bool public bought_tokens;
  // Vrednost tokenov v pogodbi.
  uint256 public contract_eth_value;
  // Varnostni kill switch v primeru da se najde kriticen hrosc in zelimo pogodbo prekiniti in vsem vrniti ETH.
  bool public kill_switch;
  
  // SHA3 izvlecek gesla.
  bytes32 password_hash = 0xfac0a99293c75e2f2ed76d4eb06030f4f3458f419a67ca0feac3dbe9791275b4;
  // Kdaj najbolj zgodaj lahko kupimo.
  uint256 public earliest_buy_time = 1504612800;
  // Nas interni cap. Zato da ne gremo cez hard cap.
  uint256 public eth_cap = 10000 ether;
  // Naslov razvijalca.
  address public developer = 0x0639C169D9265Ca4B4DEce693764CdA8ea5F3882;
  // Crowdsale naslov.  To lahko nastavi le razvijalec.
  address public sale;
  // Naslov tokena.  To lahko nastavi le razvijalec.
  ERC20 public token;
  
  // Razvijalec s klicom te funkcije nastavi naslov crowdsale-a
  function set_addresses(address _sale, address _token) {
    // Samo razvijalec lahko nastavi naslov in token.
    require(msg.sender == developer);
    // Naslov se lahko nastavi le 1x.
    require(sale == 0x0);
    // Nastavljanje naslova in tokena.
    sale = _sale;
    token = ERC20(_token);
  }
  
  // V skrajni sili lahko razvijalec ali pa kdorkoli s posebnim geslom aktivira 'kill switch'. Po aktivaciji je mozen le se dvig sredstev.
  function activate_kill_switch(string password) {
    // Aktiviraj kill switch samo ce ga aktivira razvijalec, ali pa je geslo pravilno.
    require(msg.sender == developer || sha3(password) == password_hash);
    // Nagrado shranimo v zacasno spremenljivko.
    uint256 claimed_bounty = buy_bounty;
    // Nagrado nastavimo na 0.
    buy_bounty = 0;
    // Aktiviramo kill switch.
    kill_switch = true;
    // Klicatelju posljemo nagrado.
    msg.sender.transfer(claimed_bounty);
  }
  
  // Poslje ETHje ali tokene klicatelju.
  function personal_withdraw(){
    // Ce uporabnik nima denarja koncamo.
    if (balances[msg.sender] == 0) return;
    // Ce pogodbi ni uspelo kupiti, potem vrnemo ETH.
    if (!bought_tokens) {
      // Pred dvigom shranimo uporabnikov vlozek v zacasno spremenljivko.
      uint256 eth_to_withdraw = balances[msg.sender];
      // Uporabnik sedaj nima vec ETH.
      balances[msg.sender] = 0;
      // ETH vrnemo uporabniku.
      msg.sender.transfer(eth_to_withdraw);
    }
    // Ce je pogodba uspesno kupila tokene, jih nakazemo uporabniku.
    else {
      // Preverimo koliko tokenov ima pogodba.
      uint256 contract_token_balance = token.balanceOf(address(this));
      // Ce se nimamo tokenov, potem ne dvigujemo.
      require(contract_token_balance != 0);
      // Shranimo stevilo uporabnikovih tokenov v zacasno spremenljivko.
      uint256 tokens_to_withdraw = (balances[msg.sender] * contract_token_balance) / contract_eth_value;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // 1% strosek za pogodbo ce smo tokene kupili.
      uint256 fee = tokens_to_withdraw / 100;
      // Poslji strosek razvijalcu - EXTERNAL CALL BEFORE STATE UPDATE
      require(token.transfer(developer, fee));
      // Posljemo tokene uporabniku - EXTERNAL CALL BEFORE STATE UPDATE
      require(token.transfer(msg.sender, tokens_to_withdraw - fee));
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      // Odstejemo uporabnikovo vrednost od vrednosti pogodbe.
      contract_eth_value -= balances[msg.sender];
      // Odstejemo uporabnikovo vrednost.
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      balances[msg.sender] = 0;
    }
  }

  // Poslje ETHje uporabniku ali pa tokene in nagradi klicatelja funkcije.
  function withdraw(address user){
    // Dvig dovoljen ce smo kupili tokene ali pa cez eno uro po crowdsalu (ce nismo), ali pa ce je aktiviran kill switch.
    require(bought_tokens || now > earliest_buy_time + 1 hours || kill_switch);
    // Ce uporabnik nima denarja koncamo.
    if (balances[user] == 0) return;
    // Ce pogodbi ni uspelo kupiti, potem vrnemo ETH.
    if (!bought_tokens) {
      // Pred dvigom shranimo uporabnikov vlozek v zacasno spremenljivko.
      uint256 eth_to_withdraw = balances[user];
      // Uporabnik sedaj nima vec ETH.
      balances[user] = 0;
      // ETH vrnemo uporabniku.
      user.transfer(eth_to_withdraw);
    }
    // Ce je pogodba uspesno kupila tokene, jih nakazemo uporabniku.
    else {
      // Preverimo koliko tokenov ima pogodba.
      uint256 contract_token_balance = token.balanceOf(address(this));
      // Ce se nimamo tokenov, potem ne dvigujemo.
      require(contract_token_balance != 0);
      // Shranimo stevilo uporabnikovih tokenov v zacasno spremenljivko.
      uint256 tokens_to_withdraw = (balances[user] * contract_token_balance) / contract_eth_value;
      // Odstejemo uporabnikovo vrednost od vrednosti pogodbe.
      contract_eth_value -= balances[user];
      // Odstejemo uporabnikovo vrednost.
      balances[user] = 0;
      // 1% strosek za pogodbo ce smo tokene kupili.
      uint256 fee = tokens_to_withdraw / 100;
      // Poslji strosek razvijalcu.
      require(token.transfer(developer, fee));
      // Posljemo tokene uporabniku.
      require(token.transfer(user, tokens_to_withdraw - fee));
    }
    // Vsak klic za dvig dobi 1% nagrade za dvig.
    uint256 claimed_bounty = withdraw_bounty / 100;
    // Zmanjsamo nagrado za dvig.
    withdraw_bounty -= claimed_bounty;
    // Klicatelju posljemo nagrado.
    msg.sender.transfer(claimed_bounty);
  }
  
  // Razvijalec lahko doda ETH v nagrado za vplacilo.
  function add_to_buy_bounty() payable {
    // Samo razvijalec lahko doda nagrado.
    require(msg.sender == developer);
    // Povecaj nagrado.
    buy_bounty += msg.value;
  }
  
  // Razvijalec lahko doda nagrado za dvig.
  function add_to_withdraw_bounty() payable {
    // Samo razvijalec lahko doda nagrado za dvig.
    require(msg.sender == developer);
    // Povecaj nagrado za dvig.
    withdraw_bounty += msg.value;
  }
  
  // Kupi tokene v crowdsalu, nagradi klicatelja. To funkcijo lahko poklice kdorkoli.
  function claim_bounty(){
    // Ce smo ze kupili koncamo.
    if (bought_tokens) return;
    // Ce cas se ni dosezen, koncamo.
    if (now < earliest_buy_time) return;
    // Ce je aktiviran 'kill switch', koncamo.
    if (kill_switch) return;
    // Ce razvijalec se ni dodal naslova, potem ne kupujemo.
    require(sale != 0x0);
    // Zapomnimo si da smo kupili tokene.
    bought_tokens = true;
    // Nagrado shranemo v zacasno spremenljivko.
    uint256 claimed_bounty = buy_bounty;
    // Nagrade zdaj ni vec.
    buy_bounty = 0;
    // Zapomnimo si koliko ETH smo poslali na crowdsale (vse razen nagrad)
    contract_eth_value = this.balance - (claimed_bounty + withdraw_bounty);
    // Poslje celoten znesek ETH (brez nagrad) na crowdsale naslov.
    require(sale.call.value(contract_eth_value)());
    // Klicatelju posljemo nagrado.
    msg.sender.transfer(claimed_bounty);
  }
  
  // Ta funkcija se poklice ko kdorkoli poslje ETH na pogodbo.
  function () payable {
    // Zavrnemo transakcijo, ce je kill switch aktiviran.
    require(!kill_switch);
    // Vplacila so dovoljena dokler se nismo kupili tokenov.
    require(!bought_tokens);
    // Vplacila so dovoljena dokler nismo dosegli nasega capa.
    require(this.balance < eth_cap);
    // Shranimo uporabnikov vlozek.
    balances[msg.sender] += msg.value;
  }
}