/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` with `onTokenReceived` callback before balance updates
 * 2. Placed the external call BEFORE the state modifications (violating Checks-Effects-Interactions pattern)
 * 3. Added contract existence check with `_to.code.length > 0` to make it realistic
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker calls `transfer()` to send tokens to malicious contract
 * 2. **During callback**: Malicious contract's `onTokenReceived` is triggered while balances are unchanged
 * 3. **Reentrancy**: Malicious contract calls `transfer()` again before original transaction completes
 * 4. **Transaction 2+**: Each reentrant call creates new state inconsistencies that persist across transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the malicious contract to be deployed and have specific callback logic
 * - Each exploitation attempt modifies persistent state (`balances` mapping) that affects future transactions
 * - The attack builds up through sequential calls where each transaction's state changes enable the next exploitation
 * - Single transaction attacks are limited by gas constraints, but multi-transaction attacks can drain larger amounts over time
 * 
 * **Exploitation Scenario:**
 * - Attacker deploys malicious contract with `onTokenReceived` that calls `transfer()` recursively
 * - Each call transfers tokens before the sender's balance is properly decremented
 * - State inconsistencies accumulate across multiple transactions
 * - Persistent state corruption enables continued exploitation in subsequent transactions
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple transactions to fully exploit and depends on accumulated state changes between calls.
 */
pragma solidity ^0.4.6;

contract ASWCoin {
    
    // totalSupply = maximum 210000 with 18 decimals;   
    uint256 public supply = 210000000000000000000000;  
    uint8   public decimals = 18;    
    string  public standard = 'ERC20 Token';
    string  public name = "ASWCoin";
    string  public symbol = "ASW";
    uint256 public circulatingSupply = 0;   
    uint256 availableSupply;              
    uint256 price= 1;                          
    uint256 crowdsaleClosed = 0;                 
    address multisig = msg.sender;
    address owner = msg.sender;  

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed; 
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);    

    function totalSupply() constant returns (uint256) {
        return supply;
    }
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient contract before state updates (vulnerability injection)
            uint256 codeLength;
            assembly { codeLength := extcodesize(_to) }
            if(codeLength > 0) {
                // External call to recipient contract - creates reentrancy window
                bool notificationSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
                // Continue execution regardless of notification result
            }
            // State updates happen AFTER external call - this is the vulnerability
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }
    
    modifier onlyOwner {
        if (msg.sender != owner) revert();
        _;
    }
    
    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }   
    
    function () payable {
        if (crowdsaleClosed > 0) revert();      
        if (msg.value == 0) {
          revert();
        }       
        if (!multisig.send(msg.value)) {
          revert();
        }       
        uint token = msg.value * price;       
        availableSupply = supply - circulatingSupply;
        if (token > availableSupply) {
          revert();
        }       
        circulatingSupply += token;
        balances[msg.sender] += token;
    }
    
    function setPrice(uint256 newSellPrice) onlyOwner {
        price = newSellPrice;
    }
    
    function stoppCrowdsale(uint256 newStoppSign) onlyOwner {
        crowdsaleClosed = newStoppSign;
    }       

    function setMultisigAddress(address newMultisig) onlyOwner {
        multisig = newMultisig;
    }   
    
}
