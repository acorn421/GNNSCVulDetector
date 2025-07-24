/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the recipient contract after balance updates but before allowance reduction. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `ITokenReceiver(_to).onTokenReceived(_from, _value)`
 * 2. Placed the external call after balance updates but before allowance reduction
 * 3. Used try-catch to handle callback failures gracefully
 * 4. Added check for contract code existence to only call contracts
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys malicious contract implementing `ITokenReceiver` interface
 * 2. **Initial Transaction**: Victim calls `transferFrom()` to transfer tokens to attacker's contract
 * 3. **Reentrancy Callback**: During the callback, attacker's contract:
 *    - Calls `approve()` to increase allowance for itself
 *    - Makes additional `transferFrom()` calls using the increased allowance
 *    - These calls succeed because balances were already updated but allowance hasn't been reduced yet
 * 4. **State Persistence**: The manipulated allowances persist between transactions
 * 5. **Subsequent Transactions**: Attacker can continue exploiting the manipulated state in future transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first position themselves as a recipient
 * - The exploit depends on the specific timing of the callback occurring between balance updates and allowance reduction
 * - Multiple `transferFrom()` calls are needed to drain funds beyond the original allowance
 * - The attack requires coordination between different contract functions (approve, transferFrom) across multiple transactions
 * - State changes from the reentrancy callback persist and enable continued exploitation
 * 
 * The vulnerability is realistic because recipient notifications are common in modern token standards (ERC-777), and the subtle timing of the external call creates a genuine multi-transaction reentrancy window.
 */
pragma solidity ^0.4.11;

contract ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value) public;
}

contract NGToken {

    function NGToken() public {}
    
    address public niceguy1 = 0x589A1E14208433647863c63fE2C736Ce930B956b;
    address public niceguy2 = 0x583f354B6Fff4b11b399Fad8b3C2a73C16dF02e2;
    address public niceguy3 = 0x6609867F516A15273678d268460B864D882156b6;
    address public niceguy4 = 0xA4CA81EcE0d3230c6f8CCD0ad94f5a5393f76Af8;
    address public owner = msg.sender;
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    uint256 public totalContribution = 0;
    uint256 public totalBonusTokensIssued = 0;
    uint256 public totalSupply = 0;
    bool public purchasingAllowed = true;

    function name() public constant returns (string) { return "Nice Guy Token"; }
    function symbol() public constant returns (string) { return "NGT"; }
    function decimals() public constant returns (uint256) { return 18; }
    
    function balanceOf(address _owner) public constant returns (uint256) { return balances[_owner]; }
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (2 * 32) + 4) { throw; }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        
        if (sufficientFunds && !overflowed) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_value == 0) { return false; }

        uint256 fromBalance = balances[_from];
        uint256 allowance = allowed[_from][msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool sufficientAllowance = allowance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient about the transfer via callback
            // This external call happens before allowance reduction
            if (isContract(_to)) {
                ITokenReceiver(_to).onTokenReceived(_from, _value);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            allowed[_from][msg.sender] -= _value;
            
            Transfer(_from, _to, _value);
            return true;
        } else { 
            return false; 
        }
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;        
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint256) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function enablePurchasing() public {
        if (msg.sender != owner) { throw; }

        purchasingAllowed = true;
    }

    function disablePurchasing() public {
        if (msg.sender != owner) { throw; }

        purchasingAllowed = false;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function() public payable {
        if (!purchasingAllowed) { throw; }
        
        if (msg.value == 0) { return; }

        niceguy4.transfer(msg.value/4);
        niceguy3.transfer(msg.value/4);
        niceguy2.transfer(msg.value/4);
        niceguy1.transfer(msg.value/4);

        totalContribution += msg.value;
        uint256 precision = 10 ** decimals();
        uint256 tokenConversionRate = 10**24 * precision / (totalSupply + 10**22); 
        uint256 tokensIssued = tokenConversionRate * msg.value / precision;
        totalSupply += tokensIssued;
        balances[msg.sender] += tokensIssued;
        Transfer(address(this), msg.sender, tokensIssued);
    }
}
