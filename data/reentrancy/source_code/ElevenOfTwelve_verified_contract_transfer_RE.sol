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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This violates the Checks-Effects-Interactions (CEI) pattern and creates a window for reentrancy attacks.
 * 
 * **Specific Changes Made:**
 * 1. Added a check to determine if the recipient (_to) is a contract using `_to.code.length > 0`
 * 2. Introduced an external call to `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` BEFORE updating balances
 * 3. Added a require statement to handle callback failures
 * 4. Maintained the original function signature and core logic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract with an `onTokenReceived` callback function
 * - The malicious contract receives some initial tokens through normal transfers
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transfer()` to send tokens to their malicious contract
 * - The `transfer()` function makes an external call to the malicious contract's `onTokenReceived` function BEFORE updating balances
 * - During this callback, the attacker's contract can re-enter the `transfer()` function
 * - Since balances haven't been updated yet, the attacker can repeatedly call `transfer()` to drain tokens
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The attacker needs to accumulate tokens in their malicious contract across multiple transactions to have sufficient balance for the attack
 * 2. **Contract Deployment**: The malicious contract must be deployed in a separate transaction before the attack
 * 3. **Exploitation Sequence**: The vulnerability requires a specific sequence where the attacker first gains tokens, then exploits the reentrancy in subsequent transfers
 * 
 * **Exploitation Pattern:**
 * - The malicious contract's `onTokenReceived` callback can repeatedly call `transfer()` to other addresses
 * - Each recursive call happens before the original balance update, allowing the attacker to spend the same tokens multiple times
 * - The vulnerability exploits the persistent state of the `balances` mapping across multiple function calls within the same transaction, but requires setup across multiple transactions
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world ERC-20 token callback patterns while requiring multi-transaction setup and exploitation.
 */
pragma solidity ^0.4.12;

contract ElevenOfTwelve {
    
    // totalSupply = Maximum is 210000 Coins with 18 decimals;
    // Only 1/100 of the maximum bitcoin supply.
    // Nur 1/100 vom maximalen Bitcoin Supply.
    // ElevenOfTwelve IS A VERY SEXY COIN :-)
    // Buy and get rich!

    uint256 public totalSupply = 210000000000000000000000;
    uint256 public availableSupply= 210000000000000000000000;
    uint256 public circulatingSupply = 0;
    uint8   public decimals = 18;
  
    string  public standard = 'ERC20 Token';
    string  public name = 'ElevenOfTwelve';
    string  public symbol = '11of12';            
    uint256 public crowdsalePrice = 100;                         
    uint256 public crowdsaleClosed = 0;                 
    address public daoMultisig = msg.sender;
    address public owner = msg.sender;  

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
	
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);    
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Check if recipient is a contract and has a callback function
            uint256 size;
            assembly { size := extcodesize(_to) }
            if (size > 0) {
                // Make external call before state update (violates CEI pattern)
                // In 0.4.12, we use low-level call
                if(!_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)){
                    // revert if call failed
                    revert();
                }
            }
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
        require(msg.sender == owner);
        _;
    }
	
    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    } 
	
    function () payable {
        require(crowdsaleClosed == 0);
        require(msg.value != 0);
        require(daoMultisig.send(msg.value));
        uint token = msg.value * crowdsalePrice;
		availableSupply = totalSupply - circulatingSupply;
        require(token <= availableSupply);
        circulatingSupply += token;
        balances[msg.sender] += token;
    }
	
    function setPrice(uint256 newSellPrice) onlyOwner {
        crowdsalePrice = newSellPrice;
    }
	
    function stoppCrowdsale(uint256 newStoppSign) onlyOwner {
        crowdsaleClosed = newStoppSign;
    } 

    function setMultisigAddress(address newMultisig) onlyOwner {
        daoMultisig = newMultisig;
    } 
	
}
