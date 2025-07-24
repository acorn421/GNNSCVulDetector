/*
 * ===== SmartInject Injection Details =====
 * Function      : transferTokenWithGoods
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
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call after token transfer but before final state commitment. The vulnerability exploits the inconsistent state between balances and goodsTransferArray across multiple transactions:
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * 1. **Transaction 1 (Setup)**: Owner calls transferTokenWithGoods with a malicious goodsWithdrawer contract. The tokens are transferred and goodsTransferArray is updated, but the external call reverts, causing the entire transaction to revert. However, some state changes may persist in edge cases or partial execution scenarios.
 * 
 * 2. **Transaction 2 (Exploitation)**: The malicious goodsWithdrawer contract can now be called again. Since the balances were modified before the external call, and the goodsTransferArray was updated, there's a window where the contract state is inconsistent. A sophisticated attacker can exploit this by:
 *    - Having their malicious contract's onGoodsTransfer function call back into the main contract
 *    - Manipulating the state during the callback before the original transaction completes
 *    - Creating a scenario where tokens are transferred but goods records are inconsistent
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires building up state across multiple calls
 * - The first transaction establishes the inconsistent state condition
 * - Subsequent transactions exploit the accumulated state inconsistency
 * - Single-transaction exploitation is prevented by the transaction revert mechanism, but multi-transaction patterns can exploit the race condition between state updates and external calls
 * 
 * **State Persistence Factor:**
 * - The goodsTransferArray persists between transactions
 * - The balances mapping persists between transactions  
 * - The external call creates a reentrancy opportunity that can be exploited across multiple transaction sequences
 * - The vulnerability depends on the accumulated state from previous transaction attempts
 */
pragma solidity ^0.4.16;

contract owned {
    address owner;
    function owned() public { owner = msg.sender; }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
}

contract TokenArtFinity is owned {
    
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    string public name = "ArtFinity";    //token name
    uint8 public decimals = 5;              
    string public symbol = "AT";           
    uint256 public totalSupply = 100000000000000; 
    GoodsTransferInfo[] public goodsTransferArray;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    struct GoodsTransferInfo {
        address withDrawAddress;
        uint32 goodsId;
        uint32 goodsNum;
    }

    function TokenArtFinity() public {
        balances[msg.sender] = totalSupply; 
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function transferTokenWithGoods(address goodsWithdrawer, uint256 _value, uint32 goodsId, uint32 goodsNum) public onlyOwner returns (bool success) {
        require(balances[msg.sender] >= _value && balances[goodsWithdrawer] + _value > balances[goodsWithdrawer]);
        require(goodsWithdrawer != 0x0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Transfer tokens first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[goodsWithdrawer] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add goods transfer info to pending array (state persists between transactions)
        goodsTransferArray.push(GoodsTransferInfo(goodsWithdrawer, goodsId, goodsNum));
        
        // External call for goods validation/notification - VULNERABILITY: before final state cleanup
        if (isContract(goodsWithdrawer)) {
            // Call external contract to notify about goods transfer
            // bytes4(keccak256(...)) is used in this version as abi.encodeWithSignature is 0.4.16+
            bool callSuccess = goodsWithdrawer.call(bytes4(keccak256("onGoodsTransfer(uint32,uint32)")), goodsId, goodsNum);
            // If external call fails, the transaction reverts but tokens were already transferred
            // This creates inconsistent state between balances and goodsTransferArray
            require(callSuccess);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, goodsWithdrawer, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool is_contract) {
        uint size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
        balances[_to] += _value;
        balances[_from] -= _value; 
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success)   
    { 
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
    
    function goodsTransferArrayLength() public constant returns(uint256 length) {
        return goodsTransferArray.length;
    }
}
