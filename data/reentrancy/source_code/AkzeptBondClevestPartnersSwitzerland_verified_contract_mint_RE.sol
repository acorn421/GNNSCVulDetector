/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Persistence**: Added `pendingMints` mapping to track minting sessions across transactions
 * 2. **Multi-Transaction Flow**: Modified mint to require two separate transactions:
 *    - Transaction 1: Register pending mint and notify recipient
 *    - Transaction 2: Complete the mint using stored pending value
 * 3. **Reentrancy Vulnerability**: External calls (`onMintPending` and `onMintComplete`) occur before state updates, violating the checks-effects-interactions pattern
 * 4. **Exploitation Path**: 
 *    - Owner calls mint() first time → triggers `onMintPending` callback
 *    - Malicious contract can re-enter mint() during callback, advancing to second phase
 *    - During `onMintComplete` callback, attacker can manipulate `pendingMints` state or re-enter again
 *    - State updates occur after external calls, allowing manipulation of balances and totalSupply
 * 
 * The vulnerability requires multiple transactions because:
 * - First call only sets up pending mint state
 * - Second call completes the mint but is vulnerable due to external call placement
 * - Attacker needs to accumulate state from first transaction to exploit in second transaction
 * - The `pendingMints` state persists between transactions, enabling the multi-transaction exploitation
 */
pragma solidity ^0.4.18;

contract Ownable {
    
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
    
}

contract AkzeptBondClevestPartnersSwitzerland is Ownable {
    
    string public constant name = "Akzeptbank Akzeptbond";
    
    string public constant symbol = "AKZBCPS";
    
    uint32 public constant decimals = 16;
    
    uint public totalSupply = 0;
    
    mapping (address => uint) balances;
    
    mapping (address => mapping(address => uint)) allowed;
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Add state variable to track minting sessions (add to contract state)
    mapping(address => uint) public pendingMints;
    
    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        
        // First transaction: Register pending mint
        if (pendingMints[_to] == 0) {
            pendingMints[_to] = _value;
            // Notify recipient about pending mint - external call before state update
            if (isContract(_to)) {
                // Use different variable names to avoid redeclaration error
                bool success1 = _to.call(abi.encodeWithSignature("onMintPending(uint256)", _value));
                require(success1, "Mint notification failed");
            }
            return;
        }
        
        // Second transaction: Complete the mint using pending value
        uint mintAmount = pendingMints[_to];
        
        // External call to notify before finalizing - VULNERABILITY: external call before state updates
        if (isContract(_to)) {
            bool success2 = _to.call(abi.encodeWithSignature("onMintComplete(uint256)", mintAmount));
            require(success2, "Mint completion notification failed");
        }
        
        // State updates happen after external calls - vulnerable to reentrancy
        balances[_to] += mintAmount;
        totalSupply += mintAmount;
        delete pendingMints[_to]; // Clear pending mint
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    // For Solidity <0.5.0, helper to determine if address is a contract
    function isContract(address _addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
    
    function balanceOf(address _owner) public view returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value; 
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
            return true;
        } 
        return false;
    }
    
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value 
            && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value; 
            balances[_to] += _value;
            emit Transfer(_from, _to, _value);
            return true;
        } 
        return false;
    }
    
    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public view returns (uint remaining) {
        return allowed[_owner][_spender];
    }
    
    event Transfer(address indexed _from, address indexed _to, uint _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint _value);
    
}

/*
0xc231d24Ea6E7eF51Fbe83A04507EDfdf048ECD32
renseignements annexes : confer contrats akzeptbank
*/
