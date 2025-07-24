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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the destination address before state updates. This creates the classic "checks-effects-interactions" pattern violation where the external call happens before state changes are committed.
 * 
 * **Specific Changes Made:**
 * 1. Added pre-calculation of new balances for the transfer notification
 * 2. Introduced external call to dst address using `onTokenTransfer` callback before state updates
 * 3. Moved all state modifications (allowance and balance updates) to occur AFTER the external call
 * 4. Used low-level call with abi.encodeWithSignature to make it realistic
 * 
 * **Multi-Transaction Exploitation Vector:**
 * The vulnerability requires multiple transactions to be effectively exploited due to allowance state persistence:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves a malicious contract to spend tokens via approve()
 * - Malicious contract now has allowance to call transferFrom
 * 
 * **Transaction 2 (Initial Attack):**
 * - Malicious contract calls transferFrom with itself as dst
 * - During onTokenTransfer callback, the malicious contract sees the future state (newSrcBalance, newDstBalance) but current state hasn't been updated yet
 * - Malicious contract can call transferFrom again with the same allowance (since allowance hasn't been decremented yet)
 * 
 * **Transaction 3 (Exploitation):**
 * - In the nested call, the allowance check passes because the previous call hasn't decremented it yet
 * - This allows double-spending of the same allowance across multiple calls
 * - The reentrancy creates a window where the same allowance can be used multiple times
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **Allowance State Persistence**: The allowance must be set in a previous transaction for the attack to work
 * 2. **State Accumulation**: The vulnerability exploits the timing between external calls and state updates across multiple function calls
 * 3. **Cross-Transaction Dependencies**: The attack requires the allowance to exist from previous transactions and exploits the delay in state updates
 * 
 * **Real-World Scenario:**
 * - Alice approves Bob's contract to spend 100 tokens
 * - Bob's malicious contract calls transferFrom(Alice, BobContract, 100)
 * - During the callback, Bob's contract re-enters transferFrom again before the allowance is decremented
 * - This allows Bob to transfer 200 tokens using only 100 allowance, effectively doubling the approved amount
 * 
 * This vulnerability is particularly dangerous because it preserves the function's intended behavior while creating a subtle timing window that can be exploited across multiple transactions.
 */
pragma solidity ^0.4.25;

contract MINTER {
    string public name = "AD Revenue MINTER";      //  token name
    string public symbol = "MINTER";           //  token symbol
    string public version = "2.0";
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 1000000000000000000;
    uint256 public MaxSupply = 0;
    bool public stopped = true;

    //000 000 000 000 000 000
    address owner = 0x48850F503412d8A6e3d63541F0e225f04b13a544;
    address minter = 0x47c803871c99EC7180E50dcDA989320871FcBfEE;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isMinter {
        assert(minter == msg.sender);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor () public {
        MaxSupply = 10000000000000000000;
        balanceOf[owner] = totalSupply;
        emit Transfer(0x0, owner, totalSupply);
    }

    function changeOwner(address _newaddress) isOwner public {
        owner = _newaddress;
    }

    function changeMinter(address _new_mint_address) isOwner public {
        minter = _new_mint_address;
    }

    function airdropMinting(address[] _to_list, uint[] _values) isMinter public {
        require(_to_list.length == _values.length);
        for (uint i = 0; i < _to_list.length; i++) {
            mintToken(_to_list[i], _values[i]);
        }
    }

    function setMaxSupply(uint256 maxsupply_amount) isOwner public {
      MaxSupply = maxsupply_amount;
    }

    function mintToken(address target, uint256 mintedAmount) isMinter public {
      require(MaxSupply > totalSupply);
      balanceOf[target] += mintedAmount;
      totalSupply += mintedAmount;
      emit Transfer(0, this, mintedAmount);
      emit Transfer(this, target, mintedAmount);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool success) {
        require(balanceOf[src] >= wad);
        require(allowance[src][msg.sender] >= wad);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Pre-calculate new balances for transfer notification
        uint256 newSrcBalance = balanceOf[src] - wad;
        uint256 newDstBalance = balanceOf[dst] + wad;
        
        // Notify destination contract before state updates (if it's a contract)
        uint codeLength;
        assembly { codeLength := extcodesize(dst) }
        if (codeLength > 0) {
            dst.call(abi.encodeWithSignature("onTokenTransfer(address,address,uint256,uint256,uint256)", src, msg.sender, wad, newSrcBalance, newDstBalance));
            // Continue execution even if call fails
        }
        
        // Update state after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[src][msg.sender] -= wad;
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(src, dst, wad);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}