/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after state updates. This creates a notification pattern where contract recipients are informed of token transfers, but the external call occurs after balances are already updated, violating the checks-effects-interactions pattern. The vulnerability requires multiple transactions to exploit: (1) Initial setup transaction where attacker deploys malicious contract and obtains tokens, (2) Transfer transaction that triggers the vulnerable external call, enabling reentrancy that can manipulate accumulated state across multiple nested calls. The persistent state changes in balances mapping enable compound exploitation across transaction boundaries.
 */
pragma solidity ^0.4.11;

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
        if(msg.data.length < (2 * 32) + 4) { revert(); }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        
        if (sufficientFunds && !overflowed) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            emit Transfer(msg.sender, _to, _value);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Vulnerable: External call after state updates enables reentrancy
            // Check if recipient is a contract and notify it of the transfer
            uint length;
            assembly { length := extcodesize(_to) }
            if (length > 0) {
                // This external call allows reentrancy back into this function
                // before the current transaction completes
                bool notificationSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
                // Continue execution regardless of notification success
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
            
            allowed[_from][msg.sender] -= _value;
            
            emit Transfer(_from, _to, _value);
            return true;
        } else { 
            return false; 
        }
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;        
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint256) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function enablePurchasing() public {
        if (msg.sender != owner) { revert(); }

        purchasingAllowed = true;
    }

    function disablePurchasing() public {
        if (msg.sender != owner) { revert(); }

        purchasingAllowed = false;
    }

    function() payable {
        if (!purchasingAllowed) { revert(); }
        
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
        emit Transfer(address(this), msg.sender, tokensIssued);
    }
}
