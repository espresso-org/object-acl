const _ = require('lodash')
const ObjectACL = artifacts.require('ObjectACL')
const DAOFactory = artifacts.require('@aragon/core/contracts/factory/DAOFactory')
const EVMScriptRegistryFactory = artifacts.require('@aragon/core/contracts/factory/EVMScriptRegistryFactory')
const ACL = artifacts.require('@aragon/core/contracts/acl/ACL')
const Kernel = artifacts.require('@aragon/core/contracts/kernel/Kernel')
const APMHelper = artifacts.require('APMHelper')

//contract = () => 0



contract('ObjectACL ', accounts => {
    let daoFact
    let acl
    let kernel
    let kernelBase
    let aclBase
    let APP_MANAGER_ROLE
    let objectACL
    let helper

    const root = accounts[0]
    const holder = accounts[1]
    const account3 = accounts[2]
    const DUMMY_ROLE = 1


    before(async () => {
        aclBase = await ACL.new()        
        kernelBase = await Kernel.new(true)
        helper = await APMHelper.new()
    })


    beforeEach(async () => {
        
        const regFact = await EVMScriptRegistryFactory.new()
        daoFact = await DAOFactory.new(kernelBase.address, aclBase.address, regFact.address)        

        const r = await daoFact.newDAO(root)
        kernel = Kernel.at(r.logs.filter(l => l.event == 'DeployDAO')[0].args.dao)
        acl = ACL.at(await kernel.acl())         
        
        APP_MANAGER_ROLE = await kernelBase.APP_MANAGER_ROLE()

        await acl.createPermission(holder, kernel.address, APP_MANAGER_ROLE, holder, { from: root })

        const daclReceipt = await kernel.newAppInstance(await helper.apmNamehash("object-acl"), (await ObjectACL.new()).address, { from: holder })        
        objectACL = ObjectACL.at(daclReceipt.logs.filter(l => l.event == 'NewAppProxy')[0].args.proxy)

        await acl.createPermission(root, objectACL.address, await objectACL.OBJECTACL_ADMIN_ROLE(), root)
        await acl.grantPermission(root, objectACL.address, await objectACL.OBJECTACL_ADMIN_ROLE())
        
         
        await objectACL.initialize() 

        await acl.grantPermission(objectACL.address, acl.address, await acl.CREATE_PERMISSIONS_ROLE())

    })


    describe('createObjectPermission', async () => {
        it('fires ChangeObjectPermissionManager event', async () => {
            await objectACL.createObjectPermission(root, 1, DUMMY_ROLE, root)
            
    
            await assertEvent(objectACL, { event: 'ChangeObjectPermissionManager' })
        }) 

        it('fires SetObjectPermission event', async () => {
            await objectACL.createObjectPermission(root, 1, DUMMY_ROLE, root)
    
            await assertEvent(objectACL, { event: 'SetObjectPermission' })
        }) 

    })
    
     

    describe('revokeObjectPermission', async () => {
        it('throws if not called the permission manager', async () => {
            await objectACL.createObjectPermission(root, 1, DUMMY_ROLE, root)
            assertThrow(async () => await objectACL.revokeObjectPermission(root, 1, DUMMY_ROLE, holder))
        })
      
    })   
    
    describe('grantObjectPermission', async () => {
        it('throws if not called the permission manager', async () => {
            await objectACL.createObjectPermission(root, 1, DUMMY_ROLE, root)
            assertThrow(async () => objectACL.grantObjectPermission(root, 1, DUMMY_ROLE, holder), { from: holder} )
        })
    })   
    
    describe('hasObjectPermission', async () => {
        it('returns the right permission', async () => {
            await objectACL.createObjectPermission(holder, 1, DUMMY_ROLE, root)
            assert.equal(await objectACL.hasObjectPermission.call(holder, 1, DUMMY_ROLE), true)
            assert.equal(await objectACL.hasObjectPermission.call(account3, 1, DUMMY_ROLE), false)
        })
    })      

})

async function assertThrow(fn) {
    try {
        await fn()
    } catch(e) {
        return true
    }
    assert.fail('Should have thrown')
}

async function assertEvent(contract, filter) {
    return new Promise((resolve, reject) => {
        if (!contract[filter.event])
            return reject(`No event named ${filter.event} found`)

        const event = contract[filter.event]()
        event.watch()
        event.get((error, logs) => {
            if (error)
                return reject(`Error while filtering events for ${filter.event}: ${e.message}`)

            const log = _.filter(logs, filter)

            if (log) 
                resolve(log)
            else {
                assert.fail(`Failed to find filtered event for ${filter.event}`)
                reject()
            }
            
        })
        event.stopWatching()
    })
}