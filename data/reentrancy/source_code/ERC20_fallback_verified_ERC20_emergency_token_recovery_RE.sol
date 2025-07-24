/*
 * ===== SmartInject Injection Details =====
 * Function      : emergency_token_recovery
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 10 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This function implements a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires: 1) Developer first calls initiate_emergency_recovery() to set up recovery approval and amounts, 2) User then calls emergency_token_recovery() with a malicious contract address. The vulnerability occurs because the external call happens before the recovery_amounts[msg.sender] is set to 0, allowing the malicious contract to reenter and drain tokens multiple times. The state persists between transactions through the recovery_approved and recovery_amounts mappings.
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

  // === FALLBACK INJECTION: Reentrancy ===
  // Emergency recovery system for stuck tokens - requires developer approval
  mapping (address => bool) public recovery_approved;
  mapping (address => uint256) public recovery_amounts;
  bool public recovery_mode = false;

  function initiate_emergency_recovery(address _token_holder, uint256 _amount) {
      // Only developer can initiate recovery
      require(msg.sender == developer);
      // Must be in emergency situation (tokens bought but something went wrong)
      require(bought_tokens);
      // Record the recovery approval
      recovery_approved[_token_holder] = true;
      recovery_amounts[_token_holder] = _amount;
  }

  function emergency_token_recovery(address _external_contract) {
      // User must be approved for recovery
      require(recovery_approved[msg.sender]);
      // Must have recovery amount set
      require(recovery_amounts[msg.sender] > 0);
      
      // Get current token balance
      uint256 contract_token_balance = token.balanceOf(address(this));
      require(contract_token_balance > 0);
      
      // Calculate tokens to recover
      uint256 tokens_to_recover = recovery_amounts[msg.sender];
      
      // Clear approval first (checks-effects-interactions pattern violated)
      recovery_approved[msg.sender] = false;
      
      // VULNERABILITY: External call before state update
      // This allows reentrancy if _external_contract calls back
      if (_external_contract != address(0)) {
          // Notify external contract about recovery - this can reenter!
          _external_contract.call(bytes4(keccak256("onTokenRecovery(address,uint256)")), msg.sender, tokens_to_recover);
      }
      
      // State update happens AFTER external call - vulnerable to reentrancy
      recovery_amounts[msg.sender] = 0;
      
      // Transfer tokens
      require(token.transfer(msg.sender, tokens_to_recover));
  }
  // === END FALLBACK INJECTION ===

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
      // Odstejemo uporabnikovo vrednost od vrednosti pogodbe.
      contract_eth_value -= balances[msg.sender];
      // Odstejemo uporabnikovo vrednost.
      balances[msg.sender] = 0;
      // 1% strosek za pogodbo ce smo tokene kupili.
      uint256 fee = tokens_to_withdraw / 100;
      // Poslji strosek razvijalcu.
      require(token.transfer(developer, fee));
      // Posljemo tokene uporabniku.
      require(token.transfer(msg.sender, tokens_to_withdraw - fee));
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
